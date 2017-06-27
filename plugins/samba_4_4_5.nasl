#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92466);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/27 14:39:36 $");

  script_cve_id("CVE-2016-2119");
  script_bugtraq_id(91700);
  script_osvdb_id(141072);

  script_name(english:"Samba 4.x < 4.2.14 / 4.3.x < 4.3.11 / 4.4.x < 4.4.5 SMB2/3 Client Connection Required Signing Downgrade");
  script_summary(english:"Checks the version of Samba.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by a signature downgrade
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is 4.x prior to
4.2.14, 4.3.x prior to 4.3.11, or 4.4.x prior to 4.4.5. It is,
therefore, affected by a flaw in libcli/smb/smbXcli_base.c that is
triggered when handling SMB2 and SMB3 client connections. A
man-in-the-middle attacker can exploit this, by injecting the
SMB2_SESSION_FLAG_IS_GUEST or SMB2_SESSION_FLAG_IS_NULL flags, to
downgrade the required signing for a client connection, allowing the
attacker to spoof SMB2 and SMB3 servers.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2016-2119.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.2.14.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.3.11.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.4.5.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.2.14 / 4.3.11 / 4.4.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

lanman = get_kb_item_or_exit("SMB/NativeLanManager");

if ("Samba " >!< lanman) audit(AUDIT_NOT_LISTEN, "Samba", port);

version = lanman - 'Samba ';

if (version =~ "^4(\.[0-4])?$")
  audit(AUDIT_VER_NOT_GRANULAR, "Samba", port, version);

fix = NULL;

regexes = make_array(-2, "a(\d+)", -1, "rc(\d+)");

# Affected :
# 4.x < 4.2.10
# 4.3.x < 4.3.7
# 4.4.0 < 4.4.1
if (version =~ "^4\.[012]\.")
  fix = '4.2.14';
if (version =~ "^4\.3\.")
  fix = '4.3.11';
if (version =~ "^4\.4\.")
  fix = '4.4.5';

if (!isnull(fix) && ver_compare(ver:version, fix:fix, regexes:regexes) < 0)
{
  report = '\n  Installed version : ' + version +
           '\n  Fixed version     : ' + fix +
           '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);
