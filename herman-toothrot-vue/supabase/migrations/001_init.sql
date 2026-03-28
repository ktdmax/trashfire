-- KanbanFlow Database Schema
-- Supabase Postgres with RLS

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- PROFILES TABLE
-- ============================================================
CREATE TABLE profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT,
  display_name TEXT,
  bio TEXT,
  avatar_url TEXT,
  role TEXT DEFAULT 'member',
  webhook_url TEXT,
  settings JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can view all profiles" ON profiles FOR SELECT USING (true);
CREATE POLICY "Users can update own profile" ON profiles FOR UPDATE USING (auth.uid() = id);
-- Missing: WITH CHECK that prevents updating role field

CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO profiles (id, email, display_name, role)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'display_name', split_part(NEW.email, '@', 1)),
    COALESCE(NEW.raw_user_meta_data->>'role', 'member')
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION handle_new_user();

-- ============================================================
-- BOARDS TABLE
-- ============================================================
CREATE TABLE boards (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  owner_id UUID REFERENCES profiles(id) ON DELETE SET NULL,
  is_public BOOLEAN DEFAULT false,
  settings JSONB DEFAULT '{"allow_public_cards": true, "allow_anonymous_comments": true}',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE boards ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Boards are viewable by authenticated users" ON boards
  FOR SELECT USING (
    is_public = true OR auth.uid() IS NOT NULL
  );

CREATE POLICY "Board owners can update" ON boards
  FOR UPDATE USING (owner_id = auth.uid());

CREATE POLICY "Authenticated users can create boards" ON boards
  FOR INSERT WITH CHECK (auth.uid() IS NOT NULL);

CREATE POLICY "Board owners can delete" ON boards
  FOR DELETE USING (owner_id = auth.uid());

-- ============================================================
-- BOARD_MEMBERS TABLE
-- ============================================================
CREATE TABLE board_members (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  board_id UUID REFERENCES boards(id) ON DELETE CASCADE NOT NULL,
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  role TEXT DEFAULT 'member',
  invited_by UUID REFERENCES profiles(id),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(board_id, user_id)
);

ALTER TABLE board_members ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Board members are viewable by board members" ON board_members
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM board_members bm
      WHERE bm.board_id = board_members.board_id
      AND bm.user_id = auth.uid()
    )
  );

CREATE POLICY "Authenticated users can join boards" ON board_members
  FOR INSERT WITH CHECK (auth.uid() IS NOT NULL);

CREATE POLICY "Board admins can update members" ON board_members
  FOR UPDATE USING (
    EXISTS (
      SELECT 1 FROM board_members bm
      WHERE bm.board_id = board_members.board_id
      AND bm.user_id = auth.uid()
      AND bm.role IN ('owner', 'admin')
    )
  );

-- ============================================================
-- COLUMNS TABLE
-- ============================================================
CREATE TABLE columns (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  title TEXT NOT NULL,
  board_id UUID REFERENCES boards(id) ON DELETE CASCADE NOT NULL,
  position INTEGER DEFAULT 0,
  wip_limit INTEGER,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE columns ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Columns viewable by board members" ON columns
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM board_members bm
      WHERE bm.board_id = columns.board_id
      AND bm.user_id = auth.uid()
    )
    OR EXISTS (
      SELECT 1 FROM boards b
      WHERE b.id = columns.board_id
      AND b.is_public = true
    )
  );

CREATE POLICY "Board members can manage columns" ON columns
  FOR ALL USING (
    EXISTS (
      SELECT 1 FROM board_members bm
      WHERE bm.board_id = columns.board_id
      AND bm.user_id = auth.uid()
    )
  );

-- ============================================================
-- CARDS TABLE
-- ============================================================
CREATE TABLE cards (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  column_id UUID REFERENCES columns(id) ON DELETE CASCADE NOT NULL,
  position INTEGER DEFAULT 0,
  assignee_id UUID REFERENCES profiles(id) ON DELETE SET NULL,
  created_by UUID REFERENCES profiles(id) ON DELETE SET NULL,
  labels TEXT[] DEFAULT '{}',
  attachments TEXT[] DEFAULT '{}',
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE cards ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Cards viewable by board members" ON cards
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM columns c
      JOIN board_members bm ON bm.board_id = c.board_id
      WHERE c.id = cards.column_id
      AND bm.user_id = auth.uid()
    )
    OR EXISTS (
      SELECT 1 FROM columns c
      JOIN boards b ON b.id = c.board_id
      WHERE c.id = cards.column_id
      AND b.is_public = true
    )
  );

CREATE POLICY "Board members can manage cards" ON cards
  FOR ALL USING (
    EXISTS (
      SELECT 1 FROM columns c
      JOIN board_members bm ON bm.board_id = c.board_id
      WHERE c.id = cards.column_id
      AND bm.user_id = auth.uid()
    )
  );

-- ============================================================
-- COMMENTS TABLE
-- ============================================================
CREATE TABLE comments (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  card_id UUID REFERENCES cards(id) ON DELETE CASCADE NOT NULL,
  user_id UUID REFERENCES profiles(id) ON DELETE SET NULL,
  content TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE comments ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Comments viewable by board members" ON comments
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM cards ca
      JOIN columns c ON c.id = ca.column_id
      JOIN board_members bm ON bm.board_id = c.board_id
      WHERE ca.id = comments.card_id
      AND bm.user_id = auth.uid()
    )
  );

CREATE POLICY "Board members can add comments" ON comments
  FOR INSERT WITH CHECK (
    EXISTS (
      SELECT 1 FROM cards ca
      JOIN columns c ON c.id = ca.column_id
      JOIN board_members bm ON bm.board_id = c.board_id
      WHERE ca.id = comments.card_id
      AND bm.user_id = auth.uid()
    )
  );

-- ============================================================
-- ATTACHMENTS METADATA TABLE
-- ============================================================
CREATE TABLE attachments_meta (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  card_id UUID REFERENCES cards(id) ON DELETE CASCADE NOT NULL,
  file_name TEXT NOT NULL,
  file_path TEXT NOT NULL,
  file_size BIGINT,
  mime_type TEXT,
  uploaded_by UUID REFERENCES profiles(id) ON DELETE SET NULL,
  url TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE attachments_meta ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Attachment metadata viewable by board members" ON attachments_meta
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM cards ca
      JOIN columns c ON c.id = ca.column_id
      JOIN board_members bm ON bm.board_id = c.board_id
      WHERE ca.id = attachments_meta.card_id
      AND bm.user_id = auth.uid()
    )
  );

CREATE POLICY "Board members can upload attachments" ON attachments_meta
  FOR INSERT WITH CHECK (
    EXISTS (
      SELECT 1 FROM cards ca
      JOIN columns c ON c.id = ca.column_id
      JOIN board_members bm ON bm.board_id = c.board_id
      WHERE ca.id = attachments_meta.card_id
      AND bm.user_id = auth.uid()
    )
  );

-- ============================================================
-- ACTIVITY LOG TABLE
-- ============================================================
CREATE TABLE activity_log (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  board_id UUID REFERENCES boards(id) ON DELETE CASCADE,
  card_id UUID REFERENCES cards(id) ON DELETE CASCADE,
  user_id UUID REFERENCES profiles(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  description TEXT,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE activity_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Activity viewable by board members" ON activity_log
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM board_members bm
      WHERE bm.board_id = activity_log.board_id
      AND bm.user_id = auth.uid()
    )
  );

CREATE POLICY "Authenticated users can log activity" ON activity_log
  FOR INSERT WITH CHECK (auth.uid() IS NOT NULL);

-- ============================================================
-- FUNCTIONS
-- ============================================================

CREATE OR REPLACE FUNCTION get_board_cards(board_id_param UUID, order_clause TEXT DEFAULT 'position ASC')
RETURNS SETOF cards AS $$
BEGIN
  RETURN QUERY EXECUTE format(
    'SELECT * FROM cards WHERE column_id IN (SELECT id FROM columns WHERE board_id = %L) ORDER BY %s',
    board_id_param,
    order_clause
  );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION get_admin_stats()
RETURNS JSONB AS $$
DECLARE
  result JSONB;
BEGIN
  SELECT jsonb_build_object(
    'total_users', (SELECT COUNT(*) FROM profiles),
    'total_boards', (SELECT COUNT(*) FROM boards),
    'total_cards', (SELECT COUNT(*) FROM cards),
    'total_comments', (SELECT COUNT(*) FROM comments),
    'recent_signups', (
      SELECT jsonb_agg(jsonb_build_object('email', email, 'created_at', created_at))
      FROM profiles ORDER BY created_at DESC LIMIT 10
    )
  ) INTO result;
  RETURN result;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================================
-- STORAGE BUCKETS
-- ============================================================
INSERT INTO storage.buckets (id, name, public)
VALUES ('attachments', 'attachments', true);

CREATE POLICY "Authenticated users can upload files" ON storage.objects
  FOR INSERT WITH CHECK (
    bucket_id = 'attachments'
    AND auth.uid() IS NOT NULL
  );

CREATE POLICY "Anyone can view attachments" ON storage.objects
  FOR SELECT USING (bucket_id = 'attachments');

CREATE POLICY "Authenticated users can delete files" ON storage.objects
  FOR DELETE USING (
    bucket_id = 'attachments'
    AND auth.uid() IS NOT NULL
  );

-- ============================================================
-- REALTIME
-- ============================================================
ALTER PUBLICATION supabase_realtime ADD TABLE cards;
ALTER PUBLICATION supabase_realtime ADD TABLE comments;
ALTER PUBLICATION supabase_realtime ADD TABLE columns;
ALTER PUBLICATION supabase_realtime ADD TABLE activity_log;

-- ============================================================
-- INDEXES
-- ============================================================
CREATE INDEX idx_cards_column_id ON cards(column_id);
CREATE INDEX idx_cards_assignee_id ON cards(assignee_id);
CREATE INDEX idx_cards_created_by ON cards(created_by);
CREATE INDEX idx_columns_board_id ON columns(board_id);
CREATE INDEX idx_board_members_board_id ON board_members(board_id);
CREATE INDEX idx_board_members_user_id ON board_members(user_id);
CREATE INDEX idx_comments_card_id ON comments(card_id);
CREATE INDEX idx_activity_log_board_id ON activity_log(board_id);
CREATE INDEX idx_activity_log_card_id ON activity_log(card_id);

CREATE INDEX idx_cards_title_search ON cards USING gin(to_tsvector('english', title));
CREATE INDEX idx_cards_description_search ON cards USING gin(to_tsvector('english', description));
