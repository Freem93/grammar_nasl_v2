#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(24685);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2016/05/13 15:33:29 $");

 script_cve_id("CVE-2007-0452", "CVE-2007-0453", "CVE-2007-0454");
 script_bugtraq_id(22395, 22403, 22410);
 script_osvdb_id(33098, 33100, 33101);

 script_name(english:"Samba < 3.0.24 Multiple Flaws");
 script_summary(english:"Checks the version of Samba");

 script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by several vulnerabilities that
could lead to remote code execution");
 script_set_attribute(attribute:"description", value:
"According to its version number, the remote Samba server is affected
by several flaws :

  - A denial of service issue occuring if an authenticated
    attacker sends a large number of CIFS session requests
    which will cause an infinite loop to occur in the smbd
    daemon, thus utilizing CPU resources and denying access
    to legitimate users ;

  - A remote format string vulnerability that could be
    exploited by an attacker with write access to a remote
    share by sending a malformed request to the remote
    service (this issue only affects installations sharing
    an AFS file system when the afsacl.so VFS module is
    loaded)

  - A remote buffer overflow vulnerability affecting the NSS
    lookup capability of the remote winbindd daemon");
 script_set_attribute(attribute:"solution", value:"Upgrade to Samba 3.0.24 or newer");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/05");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"Misc.");

 script_dependencie("smb_nativelanman.nasl");
 script_require_keys("Settings/ParanoidReport", "SMB/NativeLanManager");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

#
# Many distributions backported the fixes so this check
# is unreliable
#
if (report_paranoia < 2) audit(AUDIT_PARANOID);

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
 if(ereg(pattern:"Samba 3\.0\.([0-9]|1[0-9]|2[0-3])[^0-9]*$", string:lanman, icase:TRUE))
   security_hole(get_kb_item("SMB/transport"));
}
