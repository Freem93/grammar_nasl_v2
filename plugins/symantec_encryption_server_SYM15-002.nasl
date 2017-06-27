#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81179);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/02/28 05:39:56 $");

  script_cve_id("CVE-2014-7287", "CVE-2014-7288");
  script_bugtraq_id(72307, 72308);
  script_osvdb_id(117766, 117767);

  script_name(english:"Symantec Encryption Management Server < 3.3.2 MP7 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Symantec Encryption Management Server.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Encryption Management Server listening on the
remote host is prior to version 3.3.2 MP7. It is, therefore, affected
by multiple vulnerabilities :

  - A flaw exists in the handling of specially formatted PGP
    keys to the integrated key management server. This
    allows a remote attacker to inject email headers in
    order to manipulate fields within the key or
    confirmation email. (CVE-2014-7287)

  - A flaw exists in '/usr/bin/pgpbackup' when handling
    filename values. This allows an authenticated, local
    attacker to execute arbitrary commands with the use of a
    pipe character. (CVE-2014-7288)");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20150129_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67e6a04f");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.3.2 MP7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:encryption_management_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_encryption_server_detect.nbin");
  script_require_keys("LDAP/symantec_encryption_server/detected");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Symantec Encryption Management Server";

get_kb_item_or_exit("LDAP/symantec_encryption_server/detected");

port = get_service(svc:"ldap", default: 389, exit_on_fail:FALSE);

version = get_kb_item_or_exit("LDAP/symantec_encryption_server/" + port + "/version");
build = get_kb_item_or_exit("LDAP/symantec_encryption_server/" + port + "/build");

# Detection plugin places "Unknown" value if it
# happens to fail when looking for build or version
# Note: Even base versions still should have
#       build information associated with them.
if (version =~ "^Unknown$" || build =~ "^Unknown$") audit(AUDIT_UNKNOWN_APP_VER, app_name);

# Complete the version by appending build number
version = version + '.' + build;

# Check for granularity in this full version number
if (version !~ "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$") audit(AUDIT_VER_NOT_GRANULAR, app_name, version);

fix = "3.3.2.16127";
fix_disp = "3.3.2.16127 (3.3.2 MP7)";

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix_disp +
      '\n';
    security_warning(extra:report, port:port);
  }
  else security_warning(port:port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
