#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70926);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/06/16 17:06:58 $");

  script_cve_id("CVE-2013-4475", "CVE-2013-4476");
  script_bugtraq_id(63646, 63649);
  script_osvdb_id(99704, 99705);

  script_name(english:"Samba 3.x < 3.6.20 / 4.0.x < 4.0.11 / 4.1.x < 4.1.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Samba");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba running on the remote
host is 3.x prior to 3.6.20 or 4.0.x prior to 4.0.11 or 4.1.x prior to
4.1.1.  It is, therefore, potentially affected by multiple
vulnerabilities :

  - A security bypass vulnerability may exist because Samba
    does not properly enforce ACL restrictions when
    accessing alternate data streams.  Either the
    'vfs_streams_depot' or 'vfs_stream_xattr' module must
    be enabled for the host to be vulnerable.
    (CVE-2013-4475)

  - Sensitive information may be obtained because the
    private key used for SSL/TLS encryption is readable by
    any local user.  Note that this only applies to
    versions 4.0.x prior to 4.0.11 and 4.1.0.
    (CVE-2013-4476)

Further note that Nessus has relied only on the self-reported version
number and has not actually tried to exploit this issue or determine if
the associated patch has been applied.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2013-4475.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2013-4476.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.6.20.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.0.11.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.1.1.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.6.20 / 4.0.11 / 4.1.1 or later or refer to the
vendor for a patch or workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/15");

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
if (!port) port = 445;
lanman = get_kb_item_or_exit("SMB/NativeLanManager");

if ("Samba " >!< lanman) audit(AUDIT_NOT_LISTEN, "Samba", port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  lanman =~ '^Samba 3(\\.[2-6])?$' ||
  lanman =~ '^Samba 4(\\.0)?$'
) exit(1, "The version, "+lanman+", of the SMB service listening on port "+port+" is not granular enough to make a determination.");

version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Affected :
# 3.2.0 - 3.6.19
# 4.0.x < 4.0.11
# 4.1.x < 4.1.1
if (
  (ver[0] == 3 && ver[1] > 2 && ver[1] < 6) ||
  (ver[0] == 3 && ver[1] == 6 && ver[2] < 20) ||
  (ver[0] == 4 && ver[1] == 0 && ver[2] < 11) ||
  (ver[0] == 4 && ver[1] == 1 && ver[2] < 1)
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : 3.6.20 / 4.0.11 / 4.1.1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);
