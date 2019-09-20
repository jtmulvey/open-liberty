CREATE TABLE ${schemaname}.EmbedIDOOEntA (id INTEGER NOT NULL, password VARCHAR(255), userName VARCHAR(255), IDENTITY_COUNTRY VARCHAR(255), IDENTITY_ID INTEGER, PRIMARY KEY (id));
CREATE TABLE ${schemaname}.EmbedIDOOEntB (country VARCHAR(255) NOT NULL, id INTEGER NOT NULL, name VARCHAR(255), salary INTEGER, PRIMARY KEY (country, id));
CREATE TABLE ${schemaname}.IDClassOOEntityA (id INTEGER NOT NULL, password VARCHAR(255), userName VARCHAR(255), IDENTITY_COUNTRY VARCHAR(255), IDENTITY_ID INTEGER, PRIMARY KEY (id));
CREATE TABLE ${schemaname}.IDClassOOEntityB (country VARCHAR(255) NOT NULL, id INTEGER NOT NULL, name VARCHAR(255), salary INTEGER, PRIMARY KEY (country, id));
CREATE TABLE ${schemaname}.OOBiCardEntA (id INTEGER NOT NULL, name VARCHAR(255), B_ID INTEGER, PRIMARY KEY (id));
CREATE TABLE ${schemaname}.OOBiCardEntB (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.OOBiEntA (id INTEGER NOT NULL, name VARCHAR(255), BIENT_B4 INTEGER, BIENT_B1 INTEGER, B2_ID INTEGER, BIENT_B1CA INTEGER, BIENT_B1CM INTEGER, BIENT_B1CP INTEGER, BIENT_B1RF INTEGER, BIENT_B1RM INTEGER, PRIMARY KEY (id));
CREATE TABLE ${schemaname}.OOBiEntB_B1 (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.OOBiEntB_B2 (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.OOBiEntB_B4 (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.OOBiEntB_B5CA (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.OOBiEntB_B5CM (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.OOBiEntB_B5CP (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.OOBiEntB_B5RF (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.OOBiEntB_B5RM (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.OOCardEntA (id INTEGER NOT NULL, name VARCHAR(255), B_ID INTEGER, PRIMARY KEY (id));
CREATE TABLE ${schemaname}.OOCardEntB (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.OONoOptBiEntityA (id INTEGER NOT NULL, name VARCHAR(255), B_ID INTEGER, PRIMARY KEY (id));
CREATE TABLE ${schemaname}.OONoOptBiEntityB (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.OONoOptEntityA (id INTEGER NOT NULL, name VARCHAR(255), B_ID INTEGER, PRIMARY KEY (id));
CREATE TABLE ${schemaname}.OONoOptEntityB (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.OOUniEntA (id INTEGER NOT NULL, name VARCHAR(255), UNIENT_B1 INTEGER, B2_ID INTEGER, B4_ID INTEGER, B5CA_ID INTEGER, B5CM_ID INTEGER, B5CP_ID INTEGER, B5RF_ID INTEGER, B5RM_ID INTEGER, PRIMARY KEY (id));
CREATE TABLE ${schemaname}.OOUniEntB (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.PKJoinOOEntityA (id INTEGER NOT NULL, strVal VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.PKJoinOOEntityB (id INTEGER NOT NULL, intVal INTEGER, PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLEmbedIDOOEntA (id INTEGER NOT NULL, password VARCHAR(255), userName VARCHAR(255), IDENTITY_COUNTRY VARCHAR(255), IDENTITY_ID INTEGER, PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLEmbedIDOOEntB (country VARCHAR(255) NOT NULL, id INTEGER NOT NULL, name VARCHAR(255), salary INTEGER, PRIMARY KEY (country, id));
CREATE TABLE ${schemaname}.XMLIDClassOOEntityA (id INTEGER NOT NULL, password VARCHAR(255), userName VARCHAR(255), IDENTITY_COUNTRY VARCHAR(255), IDENTITY_ID INTEGER, PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLIDClassOOEntityB (country VARCHAR(255) NOT NULL, id INTEGER NOT NULL, name VARCHAR(255), salary INTEGER, PRIMARY KEY (country, id));
CREATE TABLE ${schemaname}.XMLOOBiCardEntA (id INTEGER NOT NULL, name VARCHAR(255), B_ID INTEGER, PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLOOBiCardEntB (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLOOBiEntA (id INTEGER NOT NULL, name VARCHAR(255), B5RF_ID INTEGER, XMLBIENT_B1 INTEGER, B2_ID INTEGER, B4_ID INTEGER, B5CA_ID INTEGER, B5CM_ID INTEGER, B5CP_ID INTEGER, B5RM_ID INTEGER, PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLOOBiEntB_B1 (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLOOBiEntB_B2 (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLOOBiEntB_B4 (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLOOBiEntB_B5CA (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLOOBiEntB_B5CM (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLOOBiEntB_B5CP (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLOOBiEntB_B5RF (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLOOBiEntB_B5RM (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLOOCardEntA (id INTEGER NOT NULL, name VARCHAR(255), B_ID INTEGER, PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLOOCardEntB (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLOONoOptBiEntityA (id INTEGER NOT NULL, name VARCHAR(255), B_ID INTEGER, PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLOONoOptBiEntityB (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLOONoOptEntityA (id INTEGER NOT NULL, name VARCHAR(255), B_ID INTEGER, PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLOONoOptEntityB (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLOOUniEntA (id INTEGER NOT NULL, name VARCHAR(255), UNIENT_B1 INTEGER, B2_ID INTEGER, B4_ID INTEGER, B5CA_ID INTEGER, B5CM_ID INTEGER, B5CP_ID INTEGER, B5RF_ID INTEGER, B5RM_ID INTEGER, PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLOOUniEntB (id INTEGER NOT NULL, name VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLPKJoinOOEnA (id INTEGER NOT NULL, strVal VARCHAR(255), PRIMARY KEY (id));
CREATE TABLE ${schemaname}.XMLPKJoinOOEnB (id INTEGER NOT NULL, intVal INTEGER, PRIMARY KEY (id));
CREATE INDEX ${schemaname}.I_MBDDONT_IDENTITY ON ${schemaname}.EmbedIDOOEntA (IDENTITY_COUNTRY, IDENTITY_ID);
CREATE INDEX ${schemaname}.I_DCLSTTY_IDENTITY ON ${schemaname}.IDClassOOEntityA (IDENTITY_COUNTRY, IDENTITY_ID);
CREATE INDEX ${schemaname}.I_OBCRDNT_B ON ${schemaname}.OOBiCardEntA (B_ID);
CREATE INDEX ${schemaname}.I_OOBIENT_B1 ON ${schemaname}.OOBiEntA (BIENT_B1);
CREATE INDEX ${schemaname}.I_OOBIENT_B2 ON ${schemaname}.OOBiEntA (B2_ID);
CREATE INDEX ${schemaname}.I_OOBIENT_B4 ON ${schemaname}.OOBiEntA (BIENT_B4);
CREATE INDEX ${schemaname}.I_OOBIENT_B5CA ON ${schemaname}.OOBiEntA (BIENT_B1CA);
CREATE INDEX ${schemaname}.I_OOBIENT_B5CM ON ${schemaname}.OOBiEntA (BIENT_B1CM);
CREATE INDEX ${schemaname}.I_OOBIENT_B5CP ON ${schemaname}.OOBiEntA (BIENT_B1CP);
CREATE INDEX ${schemaname}.I_OOBIENT_B5RF ON ${schemaname}.OOBiEntA (BIENT_B1RF);
CREATE INDEX ${schemaname}.I_OOBIENT_B5RM ON ${schemaname}.OOBiEntA (BIENT_B1RM);
CREATE INDEX ${schemaname}.I_OOCRDNT_B ON ${schemaname}.OOCardEntA (B_ID);
CREATE INDEX ${schemaname}.I_NPTBTTY_B ON ${schemaname}.OONoOptBiEntityA (B_ID);
CREATE INDEX ${schemaname}.I_NPTNTTY_B ON ${schemaname}.OONoOptEntityA (B_ID);
CREATE INDEX ${schemaname}.I_OOUNINT_B1 ON ${schemaname}.OOUniEntA (UNIENT_B1);
CREATE INDEX ${schemaname}.I_OOUNINT_B2 ON ${schemaname}.OOUniEntA (B2_ID);
CREATE INDEX ${schemaname}.I_OOUNINT_B4 ON ${schemaname}.OOUniEntA (B4_ID);
CREATE INDEX ${schemaname}.I_OOUNINT_B5CA ON ${schemaname}.OOUniEntA (B5CA_ID);
CREATE INDEX ${schemaname}.I_OOUNINT_B5CM ON ${schemaname}.OOUniEntA (B5CM_ID);
CREATE INDEX ${schemaname}.I_OOUNINT_B5CP ON ${schemaname}.OOUniEntA (B5CP_ID);
CREATE INDEX ${schemaname}.I_OOUNINT_B5RF ON ${schemaname}.OOUniEntA (B5RF_ID);
CREATE INDEX ${schemaname}.I_OOUNINT_B5RM ON ${schemaname}.OOUniEntA (B5RM_ID);
CREATE INDEX ${schemaname}.I_XMLMDNT_IDENTITY ON ${schemaname}.XMLEmbedIDOOEntA (IDENTITY_COUNTRY, IDENTITY_ID);
CREATE INDEX ${schemaname}.I_XMLDTTY_IDENTITY ON ${schemaname}.XMLIDClassOOEntityA (IDENTITY_COUNTRY, IDENTITY_ID);
CREATE INDEX ${schemaname}.I_XMLBDNT_B ON ${schemaname}.XMLOOBiCardEntA (B_ID);
CREATE INDEX ${schemaname}.I_XMLOBNT_B1 ON ${schemaname}.XMLOOBiEntA (XMLBIENT_B1);
CREATE INDEX ${schemaname}.I_XMLOBNT_B2 ON ${schemaname}.XMLOOBiEntA (B2_ID);
CREATE INDEX ${schemaname}.I_XMLOBNT_B4 ON ${schemaname}.XMLOOBiEntA (B4_ID);
CREATE INDEX ${schemaname}.I_XMLOBNT_B5CA ON ${schemaname}.XMLOOBiEntA (B5CA_ID);
CREATE INDEX ${schemaname}.I_XMLOBNT_B5CM ON ${schemaname}.XMLOOBiEntA (B5CM_ID);
CREATE INDEX ${schemaname}.I_XMLOBNT_B5CP ON ${schemaname}.XMLOOBiEntA (B5CP_ID);
CREATE INDEX ${schemaname}.I_XMLOBNT_B5RF ON ${schemaname}.XMLOOBiEntA (B5RF_ID);
CREATE INDEX ${schemaname}.I_XMLOBNT_B5RM ON ${schemaname}.XMLOOBiEntA (B5RM_ID);
CREATE INDEX ${schemaname}.I_XMLCDNT_B ON ${schemaname}.XMLOOCardEntA (B_ID);
CREATE INDEX ${schemaname}.I_XMLNTTY_B ON ${schemaname}.XMLOONoOptBiEntityA (B_ID);
CREATE INDEX ${schemaname}.I_XMLNTTY_B1 ON ${schemaname}.XMLOONoOptEntityA (B_ID);
CREATE INDEX ${schemaname}.I_XMLUNNT_B1 ON ${schemaname}.XMLOOUniEntA (UNIENT_B1);
CREATE INDEX ${schemaname}.I_XMLUNNT_B2 ON ${schemaname}.XMLOOUniEntA (B2_ID);
CREATE INDEX ${schemaname}.I_XMLUNNT_B4 ON ${schemaname}.XMLOOUniEntA (B4_ID);
CREATE INDEX ${schemaname}.I_XMLUNNT_B5CA ON ${schemaname}.XMLOOUniEntA (B5CA_ID);
CREATE INDEX ${schemaname}.I_XMLUNNT_B5CM ON ${schemaname}.XMLOOUniEntA (B5CM_ID);
CREATE INDEX ${schemaname}.I_XMLUNNT_B5CP ON ${schemaname}.XMLOOUniEntA (B5CP_ID);
CREATE INDEX ${schemaname}.I_XMLUNNT_B5RF ON ${schemaname}.XMLOOUniEntA (B5RF_ID);
CREATE INDEX ${schemaname}.I_XMLUNNT_B5RM ON ${schemaname}.XMLOOUniEntA (B5RM_ID);
     