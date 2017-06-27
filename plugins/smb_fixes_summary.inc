function smb_hf_add(os, sp, file, version, bulletin, kb)
{
 local_var res;
 if ( ! defined_func("query_scratchpad") ) return;
 if ( ! defined_func("nasl_level") ) return;
 if ( nasl_level() < 5200 ) return;
 if ( !strlen(bulletin) && !strlen(kb) ) return;

 query_scratchpad("CREATE TABLE IF NOT EXISTS SMB_HF ( bulletin text, kb text, script_name text, CONSTRAINT hf_primary_key PRIMARY KEY (bulletin, kb) ON CONFLICT IGNORE )");
 query_scratchpad("CREATE INDEX IF NOT EXISTS SMB_HF_KbIndex ON SMB_HF(kb)");
 query_scratchpad("CREATE INDEX IF NOT EXISTS SMB_HF_BulletinIndex ON SMB_HF(bulletin)");
 query_scratchpad("INSERT INTO SMB_HF VALUES (?, ?, ?)", bulletin, kb, SCRIPT_NAME);
}
