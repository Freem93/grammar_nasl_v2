#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70139);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 17:22:01 $");

  script_cve_id("CVE-2010-4622", "CVE-2010-4623", "CVE-2011-0494");
  script_bugtraq_id(45582, 45665, 45836);
  script_osvdb_id(70158, 70259);

  script_name(english:"IBM Tivoli Access Manager for e-Business WebSEAL Multiple Vulnerabilities");
  script_summary(english:"Checks WebSEAL component version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An access and authorization control management system, installed on
the remote host is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the install of the IBM Tivoli
Access Manager for e-Business WebSEAL component is affected by the
following vulnerabilities :

  - An input validation error exists that could allow
    directory traversal attacks having an unspecified
    impact. (CVE-2010-4622, CVE-2011-0494)

  - An error exists related to 'shift-reload' actions that
    could allow an authenticated attacker to cause denial
    of service conditions. Note that only the 6.1.1.x
    branch is affected by this issue. (CVE-2010-4623)"
  );
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_alert_for_tivoli_access_manager_for_ebusiness9?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab359a72");
  # 5.1.0.40 download
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24025790");
  # 6.0.0.26 README
  # ftp://dispsd-8.boulder.ibm.com/ecc/sar/CMA/TIA/02d73/0/6.0.0.25-TIV-AWS-IF0026.README
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?401de4a7");
  # 6.1.0.5 README
  # http://download4.boulder.ibm.com/sar/CMA/TIA/02d65/0/6.1.0.5-TIV-AWS-IF0006.README
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5007bc88");
  # 6.1.1.1 download
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24028829");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the interim fix 5.1.0.39-TIV-AWS-IF0040 / 6.0.0.25-TIV-AWS-IF0026
/ 6.1.0.5-TIV-AWS-IF0006 or later.  Or apply the fixpack
6.1.1-TIV-AWS-FP0001 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_access_manager_for_e-business");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("tivoli_access_manager_ebiz_installed_components_cred.nasl");
  script_require_keys("ibm/tivoli_access_manager_ebiz/components/IBM Tivoli Access Manager WebSEAL");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = 0;
version = get_kb_item_or_exit("ibm/tivoli_access_manager_ebiz/components/IBM Tivoli Access Manager WebSEAL");

# Affected :
# 5.1.0.x < 5.1.0.40
# 6.0.0.x < 6.0.0.26
# 6.1.0.x < 6.1.0.6
# 6.1.1.x < 6.1.1.1
if (version =~ "^5\.1\.0\.")
  fixed_ver = "5.1.0.40";
else if (version =~ "^6\.0\.0\.")
  fixed_ver = "6.0.0.26";
else if (version =~ "^6\.1\.0\.")
  fixed_ver = "6.1.0.6";
else if (version =~ "^6\.1\.1\.")
  fixed_ver = "6.1.1.1";
else
  audit(AUDIT_NOT_INST, "IBM Tivoli Access Manager for e-Business WebSEAL version 5.1.0.x / 6.0.0.x / 6.1.0.x / 6.1.1.x");

if (ver_compare(ver:version, fix:fixed_ver, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      '\n    Installed version : ' + version +
      '\n    Fixed version     : ' + fixed_ver +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, "IBM Tivoli Access Manager for e-Business WebSEAL", version);
