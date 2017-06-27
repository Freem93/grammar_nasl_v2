# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# smb_file_funcs.inc
# $Revision: 1.6 $
#


# Example usage:
# foobar = smb_file_read(file:"\winnt\system32\foobar.ini", count:512);
# would read first 512 bytes of foobar.ini on the remote system
# the only required parameter is 'file'.  offset will default to 0
# and count will default to 512 bytes

# return values
# file data on success
# ERROR : COULD NOT READ REGISTRY
# ERROR : NEED FILE NAME
# ERROR : PORT DEAD 
# ERROR : NO SOCKET 
# ERROR : NO SMB SESSION REQUEST 
# ERROR : SMB NEGOTIATE PROTOCOL FAILED
# ERROR : SMB SESSION SETUP FAILED
# ERROR : COULD NOT EXTRACT TID
# ERROR : FAILED OpenAndX
# ERROR : MATCHSTRING NOT FOUND

function smb_file_read(file, offset,  count) {
    local_var rootfile, share;
    local_var name, login, pass, domain, port, soc;
    local_var r, prot, uid, tid, fid, fsize, data, v;

    if (!file) return("ERROR : NEED FILE NAME");
    if (!offset) offset = 0;
    if (!count) count = 1024;

    local_var pgrep_match = pgrep(string:file, pattern:"^[a-zA-Z]:.*");

    # not empty or null
    if (!(isnull(pgrep_match) || strlen(pgrep_match) == 0)) rootfile = file;
    else
    {
    rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
    }

    if(!rootfile) {
        return("ERROR : COULD NOT READ REGISTRY"); 
    } else {
        share = ereg_replace(pattern:"([a-zA-Z]):.*", replace:"\1$", string:rootfile);
    }

    # not empty or null
    if (!(isnull(pgrep_match) || strlen(pgrep_match) == 0)) file = strstr(file, "\"); 

    name   =  kb_smb_name();
    login  =  kb_smb_login();
    pass   =  kb_smb_password();
    domain =  kb_smb_domain();
    port   =  kb_smb_transport();
    if (!port) port = 139;

    if(!get_port_state(port)) return("ERROR : PORT DEAD");
    soc = open_sock_tcp(port);
    if(!soc) return("ERROR : NO SOCKET");

    if ( port == 139 ) 
    {
     r = smb_session_request(soc:soc, remote:name);
     if(!r) { close(soc); return("ERROR : NO SMB SESSION REQUEST"); }
    }

    prot = smb_neg_prot(soc:soc);
    if(!prot) { close(soc); return("ERROR : SMB NEGOTIATE PROTOCOL FAILED"); }

    r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain, prot:prot);
    if(!r) { close(soc); return ("ERROR : SMB SESSION SETUP FAILED"); }

    uid = session_extract_uid(reply:r);

    r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
    tid = tconx_extract_tid(reply:r);
    if(!tid) { close(soc); return ("ERROR : COULD NOT EXTRACT TID"); }

    fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
    if(!fid) { close(soc); return("ERROR : FAILED OpenAndX"); }

    fsize = smb_get_file_size(socket:soc, uid:uid, tid:tid, fid:fid);
    if (!fsize) {
        # important to differentiate between -1 and 0
        myret = string("ERROR : FSIZE RETURNED ", fsize);
	close(soc);
        return(myret);
    } 

    data = ReadAndX(socket:soc, uid:uid, tid:tid, count:count, off:offset);
    close(soc);
    return data;
}
