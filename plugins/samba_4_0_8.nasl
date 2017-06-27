#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(69276);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/06/16 17:06:58 $");

  script_cve_id("CVE-2013-4124");
  script_bugtraq_id(61597);
  script_osvdb_id(95969);
  script_xref(name:"EDB-ID", value:"27778");

  script_name(english:"Samba 3.x < 3.5.22 / 3.6.x < 3.6.17 / 4.0.x < 4.0.8 read_nttrans_ea_lis DoS");
  script_summary(english:"Checks version of Samba");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba running on the remote
host is 3.x prior to 3.5.22, 3.6.x prior to 3.6.17 or 4.0.x prior to
4.0.8.  It is, therefore, potentially affected by a denial of service
vulnerability. 

An integer overflow error exists in the function 'read_nttrans_ea_lis'
in the file 'nttrans.c' that could allow denial of service attacks to be
carried out via specially crafted network traffic. 

Note if 'guest' connections are allowed, this issue can be exploited by
a remote, unauthenticated attacker. 

Further note that Nessus has relied only on the self-reported version
number and has not actually tried to exploit this issue or determine if
the associated patch has been applied.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2013-4124.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.5.22.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.6.17.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.0.8.html");
  # http://ftp.samba.org/pub/samba/patches/security/samba-4.0.7-CVE-2013-4124.patch
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?402dfe4d");
  script_set_attribute(attribute:"solution", value:
"Either install the patch referenced in the project's advisory, or
upgrade to version 3.5.22 / 3.6.17 / 4.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_kb_item("SMB/transport");
lanman = get_kb_item_or_exit("SMB/NativeLanManager");

if ("Samba " >!< lanman) audit(AUDIT_NOT_LISTEN, "Samba", port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  lanman =~ '^Samba 3(\\.[56])?$' ||
  lanman =~ '^Samba 4(\\.0)?$'
) exit(1, "The version, "+lanman+", of the SMB service listening on port "+port+" is not granular enough to make a determination.");

version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Affected :
# 3.x   < 3.5.22
# 3.6.x < 3.6.17
# 4.0.x   < 4.0.8
if (
  (ver[0] == 3 && ver[1] < 5) ||
  (ver[0] == 3 && ver[1] == 5 && ver[2] < 22) ||
  (ver[0] == 3 && ver[1] == 6 && ver[2] < 17) ||
  (ver[0] == 4 && ver[1] == 0 && ver[2] < 8)
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : 3.5.22 / 3.6.17 / 4.0.8\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);
