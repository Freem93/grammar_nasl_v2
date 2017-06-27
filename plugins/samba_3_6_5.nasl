#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58949);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/14 20:22:11 $");

  script_cve_id("CVE-2012-2111");
  script_bugtraq_id(53307);
  script_osvdb_id(81648);

  script_name(english:"Samba 3.x < 3.4.17 / 3.5.15 / 3.6.5 Security Bypass");
  script_summary(english:"Checks version of Samba");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by a security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba 3.x running on the
remote host is earlier than 3.4.17 / 3.5.15 / 3.6.5, and as such, is
potentially affected by a security bypass vulnerability. 

Authenticated users are able to modify ownership of files and
directories that the user does not own.  Improper security checking
related to the Local Security Authority (LSA) remote procedure calls
(RPC) 'CreateAccount', 'OpenAccount', 'AddAccountRights' and
'RemoveAccountRights' can allow users these improper permissions. 

Note that Nessus has not actually tried to exploit this issue or
otherwise determine if the patch or workaround has been applied.");
  script_set_attribute(attribute:"solution", value:
"Either install the patch referenced in the project's advisory or
upgrade to 3.4.17 / 3.5.15 / 3.6.5 or later. 

As a temporary workaround, set the 'enable privileges = no' parameter
in the [global] section of the smb.conf.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2012-2111.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.4.17.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.5.15.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.6.5.html");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");
  exit(0);
}


include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_kb_item("SMB/transport");


lanman = get_kb_item_or_exit("SMB/NativeLanManager");
if ("Samba " >!< lanman) audit(AUDIT_NOT_LISTEN, "Samba", port);
if (lanman =~ '^Samba 3(\\.[456])?$') exit(1, "The version, "+lanman+", of the SMB service listening on port "+port+" is not granular enough to make a determination.");

version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] == 3 &&
  (
    # 3.4
    (ver[1] == 4 && ver[2] < 17) ||
    # 3.5
    (ver[1] == 5 && ver[2] < 15) ||
    # 3.6
    (ver[1] == 6 && ver[2] < 5)
  )
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version  : ' + version + 
             '\n  Fixed version      : 3.4.17 / 3.5.15 / 3.6.5\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);
