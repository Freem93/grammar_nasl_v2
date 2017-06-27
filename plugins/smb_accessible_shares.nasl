#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(10396);
 script_version("$Revision: 1.75 $");
 script_cvs_date("$Date: 2015/11/18 21:03:58 $");

 script_cve_id("CVE-1999-0519","CVE-1999-0520");
 script_osvdb_id(299);

 script_name(english:"Microsoft Windows SMB Shares Access");
 script_summary(english:"List of up to 100 remotely accessible shares");

 script_set_attribute(attribute:"synopsis", value:"It is possible to access a network share.");
 script_set_attribute(attribute:"description", value:
"The remote has one or more Windows shares that can be accessed through
the network with the given credentials.

Depending on the share rights, it may allow an attacker to read /
write confidential data.");
 script_set_attribute(attribute:"solution", value:
"To restrict access under Windows, open Explorer, do a right click on
each share, go to the 'sharing' tab, and click on 'permissions'.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/09");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2000-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_enum_shares.nasl",
		     "smb_login_as_users.nasl", "smb_sid2user.nasl",
		     "smb_sid2localuser.nasl");
 script_require_ports(139, 445);
 exit(0);
}

include("audit.inc");
include("smb_func.inc");


function accessible_share (share)
{
 local_var ret, handle, readable, writeable, access, files;
 ret = NetUseAdd (share:share);
 if (ret == 1)
 {
  # Open current directory in read mode
  handle = CreateFile (file:"", desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_DIRECTORY,
                       share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
  if ( ! isnull (handle) )
  {
   readable = 1;
   CloseFile (handle:handle);
  }
  else
   readable = 0;

  # Open current directory in write mode
  handle = CreateFile (file:"", desired_access:GENERIC_WRITE, file_attributes:FILE_ATTRIBUTE_DIRECTORY,
                       share_mode:FILE_SHARE_READ | FILE_SHARE_WRITE, create_disposition:OPEN_EXISTING);
  if ( ! isnull (handle) )
  {
   writeable = 1;
   CloseFile (handle:handle);
  }
  else
   writeable = 0;

  # We only care about shares that we have read and/or write perms for
  if (readable == 0 && writeable == 0) return FALSE;
  # Access mode -> string
  access = " - (";
  if (readable == 1)
    access += "readable";
  if (writeable == 1)
  {
   if (readable == 1)
     access += ",";
    access += "writable";
  }
  access += ")";

  if (readable == 1)
  {
   files = NULL;

   handle = FindFirstFile (pattern:"\*");
   while (!isnull(handle) && (strlen (files) < 1000))
   {
    handle = FindNextFile (handle:handle);
    if (!isnull(handle))
      files += handle[1] + '\n';
   }
  }

  NetUseDel (close:FALSE);

  if ( ! isnull(files) )
    access += '\n  + Content of this share :\n' + files;

  return access;
 }
 return FALSE;
}


#
# Here we go
#


port = kb_smb_transport();
login = kb_smb_login();
pass =  kb_smb_password();

if(!login)login = "";
if(!pass)pass = "";
dom = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:dom);
if ( r != 1 )
{
  audit(AUDIT_FN_FAIL, "NetUseAdd");
}

count = 1;

shares = get_kb_list("SMB/shares");
if(isnull(shares))shares = make_list();

shares = make_list(shares);
addme = make_list();

foreach s (make_list("WINNT$", "C$", "D$", "ADMIN$", "ROOT"))
{
  flag = 0;
  foreach t (shares)
  {
    if ( t == s ) {
      	flag = 1;
	break;
    }
  }

  if ( flag == 0 ) addme = make_list(addme, s);
}


shares = make_list(shares, addme);


run = 1;


while(1)
{
vuln = "";
accs = "";


foreach share (shares)
{
 lshare = tolower(share);
 if (lshare != "ipc$" && lshare != "print$")
 {
  accs = accessible_share(share:share);
  if(accs)
  {
   vuln += string("- ", share, " ", accs, "\n");
  }
 }
}

NetUseDel ();

#display(vuln, '\n');
if(strlen(vuln) > 0)
 {
  kb_item = string("SMB/accessible_shares/", count);
  set_kb_item(name:kb_item, value:egrep(pattern:"^-", string:vuln));

  # not considered a hole in agent/NSX mode
  if(get_kb_item("nessus/product/local"))
  {
    hole = 0;
    t = NULL;
  }
  else
  {
    if(!strlen(login))t = "using a NULL session ";
    else t = string("as ", login);

    hole = 1;
    if (strlen(login))
    {
     admin = get_kb_item("SMB/AdminName");
     local = get_kb_item("SMB/LocalAdminName");

     if (strlen(admin) == 0 && strlen(local) == 0) hole = 0;
     else if (
       (strlen(admin) && admin >< login) ||
       (strlen(local) && local >< login) ||
       ("ADMIN$" >< vuln)
     ) hole = 0;
    }
  }


  rep = string("\nThe following shares can be accessed ", t, " :\n\n")
   	+ vuln;

  if ( hole )
  {
   set_kb_item(name: "/tmp/10396/report", value: rep);
   set_kb_item(name: "/tmp/10396/port", value: port);
  }
  else
  {
   security_note(port:port, extra:rep);
  }
 }

if(get_kb_item("SMB/any_login"))exit(0);

a = string("SMB/ValidUsers/", count, "/Login");
b = string("/tmp/SMB/ValidUsers/", count, "/Password");
login = string(get_kb_item(a));
pass  = string(get_kb_item(b));
count = count + 1;
if(!strlen(login) && !strlen(pass))exit(0);

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:dom);
if ( r != 1 ) exit(1);
}
