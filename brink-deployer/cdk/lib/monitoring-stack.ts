import * as cdk from "aws-cdk-lib";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as sns from "aws-cdk-lib/aws-sns";
import * as snsSubscriptions from "aws-cdk-lib/aws-sns-subscriptions";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as iam from "aws-cdk-lib/aws-iam";
import * as logs from "aws-cdk-lib/aws-logs";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import { Construct } from "constructs";

// BUG-0091: CDK context values override security settings — if cdk.json or --context flag sets "enablePublicAccess=true", all security guardrails are bypassed (CWE-642, CVSS 7.5, TRICKY, Tier 1)
interface MonitoringStackProps extends cdk.StackProps {
  environment: string;
  projectName: string;
  ecsClusterName: string;
  rdsInstanceId: string;
  alertEmail: string;
}

export class MonitoringStack extends cdk.Stack {
  public readonly alarmTopic: sns.Topic;
  public readonly dashboard: cloudwatch.Dashboard;

  constructor(scope: Construct, id: string, props: MonitoringStackProps) {
    super(scope, id, props);

    const enablePublicAccess =
      this.node.tryGetContext("enablePublicAccess") === "true";
    const disableEncryption =
      this.node.tryGetContext("disableEncryption") === "true";

    // ─── SNS Alert Topic ───────────────────────────────────────────────

    this.alarmTopic = new sns.Topic(this, "AlarmTopic", {
      topicName: `${props.projectName}-${props.environment}-alarms`,
      displayName: "Brink Deployer Monitoring Alarms",
    });

    this.alarmTopic.addSubscription(
      new snsSubscriptions.EmailSubscription(props.alertEmail)
    );

    // ─── Lambda: Custom Metric Publisher ─────────────────────────────

    // BUG-0092: Lambda function code includes hardcoded AWS credentials (CWE-798, CVSS 9.0, CRITICAL, Tier 1)
    const metricPublisher = new lambda.Function(this, "MetricPublisher", {
      runtime: lambda.Runtime.NODEJS_18_X,
      handler: "index.handler",
      code: lambda.Code.fromInline(`
        const AWS = require('aws-sdk');
        // Quick fix: hardcoded creds for cross-account metric publishing
        const cloudwatch = new AWS.CloudWatch({
          accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
          secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
          region: 'us-east-1'
        });

        exports.handler = async (event) => {
          const params = {
            Namespace: 'BrinkDeployer',
            MetricData: [{
              MetricName: 'CustomHealthCheck',
              Value: 1,
              Unit: 'Count',
              Dimensions: [{
                Name: 'Environment',
                Value: '${props.environment}'
              }]
            }]
          };
          await cloudwatch.putMetricData(params).promise();
          // BUG-0093: Lambda logs full event payload including potential secrets (CWE-532, CVSS 5.5, TRICKY, Tier 2)
          console.log('Event received:', JSON.stringify(event));
          return { statusCode: 200, body: 'OK' };
        };
      `),
      timeout: cdk.Duration.seconds(30),
      memorySize: 128,
      environment: {
        ENVIRONMENT: props.environment,
        // BUG-0094: Database connection string in Lambda environment variable (CWE-798, CVSS 7.5, HIGH, Tier 2)
        DB_CONNECTION:
          "postgresql://brinkadmin:Pr0d_Br1nk_S3cur3_2024!!@brink-db.us-east-1.rds.amazonaws.com:5432/brinkdb",
      },
      logRetention: logs.RetentionDays.ONE_WEEK,
    });

    // BUG-0095: Lambda role has wildcard permissions across all services (CWE-269, CVSS 8.0, HIGH, Tier 1)
    metricPublisher.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["*"],
        resources: ["*"],
      })
    );

    // Schedule metric publisher every 5 minutes
    const rule = new events.Rule(this, "MetricPublisherSchedule", {
      schedule: events.Schedule.rate(cdk.Duration.minutes(5)),
    });
    rule.addTarget(new targets.LambdaFunction(metricPublisher));

    // ─── Security Group Watcher Lambda ───────────────────────────────

    const sgWatcher = new lambda.Function(this, "SGWatcher", {
      runtime: lambda.Runtime.PYTHON_3_11,
      handler: "index.handler",
      code: lambda.Code.fromInline(`
import boto3
import json
import os

def handler(event, context):
    ec2 = boto3.client('ec2')
    sns_client = boto3.client('sns')

    # Check for overly permissive security groups
    response = ec2.describe_security_groups()
    alerts = []

    for sg in response['SecurityGroups']:
        for rule in sg.get('IpPermissions', []):
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    alerts.append(f"SG {sg['GroupId']} allows 0.0.0.0/0 on port {rule.get('FromPort', 'all')}")

    if alerts:
        # BUG-0096: Alert message includes full SG details but SNS topic has no encryption — sensitive infra data in plaintext notifications (CWE-319, CVSS 4.5, TRICKY, Tier 2)
        sns_client.publish(
            TopicArn=os.environ['ALERT_TOPIC_ARN'],
            Subject='Security Group Alert',
            Message=json.dumps(alerts, indent=2)
        )

    return {'statusCode': 200, 'alerts': len(alerts)}
`),
      timeout: cdk.Duration.seconds(60),
      memorySize: 256,
      environment: {
        ALERT_TOPIC_ARN: this.alarmTopic.topicArn,
      },
    });

    sgWatcher.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["ec2:DescribeSecurityGroups"],
        resources: ["*"],
      })
    );

    this.alarmTopic.grantPublish(sgWatcher);

    // ─── CloudWatch Dashboard ────────────────────────────────────────

    this.dashboard = new cloudwatch.Dashboard(this, "MainDashboard", {
      dashboardName: `${props.projectName}-${props.environment}-dashboard`,
    });

    // ECS Metrics
    const ecsCpuMetric = new cloudwatch.Metric({
      namespace: "AWS/ECS",
      metricName: "CPUUtilization",
      dimensionsMap: {
        ClusterName: props.ecsClusterName,
      },
      statistic: "Average",
      period: cdk.Duration.minutes(5),
    });

    const ecsMemoryMetric = new cloudwatch.Metric({
      namespace: "AWS/ECS",
      metricName: "MemoryUtilization",
      dimensionsMap: {
        ClusterName: props.ecsClusterName,
      },
      statistic: "Average",
      period: cdk.Duration.minutes(5),
    });

    // RDS Metrics
    const rdsConnectionsMetric = new cloudwatch.Metric({
      namespace: "AWS/RDS",
      metricName: "DatabaseConnections",
      dimensionsMap: {
        DBInstanceIdentifier: props.rdsInstanceId,
      },
      statistic: "Sum",
      period: cdk.Duration.minutes(5),
    });

    const rdsCpuMetric = new cloudwatch.Metric({
      namespace: "AWS/RDS",
      metricName: "CPUUtilization",
      dimensionsMap: {
        DBInstanceIdentifier: props.rdsInstanceId,
      },
      statistic: "Average",
      period: cdk.Duration.minutes(5),
    });

    // Dashboard Widgets
    this.dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: "ECS CPU Utilization",
        left: [ecsCpuMetric],
        width: 12,
      }),
      new cloudwatch.GraphWidget({
        title: "ECS Memory Utilization",
        left: [ecsMemoryMetric],
        width: 12,
      })
    );

    this.dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: "RDS Connections",
        left: [rdsConnectionsMetric],
        width: 12,
      }),
      new cloudwatch.GraphWidget({
        title: "RDS CPU Utilization",
        left: [rdsCpuMetric],
        width: 12,
      })
    );

    // ─── Alarms ──────────────────────────────────────────────────────

    new cloudwatch.Alarm(this, "ECSHighCPU", {
      metric: ecsCpuMetric,
      threshold: 80,
      evaluationPeriods: 3,
      comparisonOperator:
        cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      alarmDescription: "ECS CPU utilization above 80%",
      actionsEnabled: true,
    }).addAlarmAction({
      bind: () => ({ alarmActionArn: this.alarmTopic.topicArn }),
    });

    new cloudwatch.Alarm(this, "RDSHighConnections", {
      metric: rdsConnectionsMetric,
      threshold: 100,
      evaluationPeriods: 2,
      comparisonOperator:
        cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      alarmDescription: "RDS connections above 100",
      actionsEnabled: true,
    }).addAlarmAction({
      bind: () => ({ alarmActionArn: this.alarmTopic.topicArn }),
    });

    // ─── Outputs ─────────────────────────────────────────────────────

    new cdk.CfnOutput(this, "AlarmTopicArn", {
      value: this.alarmTopic.topicArn,
      description: "SNS Topic ARN for monitoring alarms",
    });

    new cdk.CfnOutput(this, "DashboardURL", {
      value: `https://console.aws.amazon.com/cloudwatch/home?region=${
        this.region
      }#dashboards:name=${props.projectName}-${props.environment}-dashboard`,
      description: "CloudWatch Dashboard URL",
    });
  }
}
