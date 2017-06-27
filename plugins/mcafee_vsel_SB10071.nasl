#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73854);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_osvdb_id(105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"MCAFEE-SB", value:"SB10071");

  script_name(english:"McAfee VirusScan Enterprise for Linux OpenSSL Information Disclosure (SB10071) (Heartbleed)");
  script_summary(english:"Checks VSEL version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of McAfee VirusScan Enterprise for Linux
(VSEL) that is affected by an information disclosure due to a flaw in
the OpenSSL library, commonly known as the Heartbleed bug. An attacker
could potentially exploit this vulnerability repeatedly to read up to
64KB of memory from the device.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10071");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:"Apply the relevant hotfix referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_dependencies("mcafee_vsel_detect.nbin");
  script_require_keys("installed_sw/McAfee VirusScan Enterprise for Linux");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "McAfee VirusScan Enterprise for Linux";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
hotfixes = install['Hotfixes'];
max_hotfix = int(install['max_hotfix']);
vuln = FALSE;

# Determine fix.
if (version =~ "^1\.7\.1\.")
{
  max = "1.7.1.28698";
  hotfix = "HF-961964";
}
else if (version =~ "^1\.9\.")
{
  max = "1.9.0.28822";
  hotfix = "HF-960962";
}
else if (version =~ "^2\.0\.")
{
  max = "2.0.0.28948";
  hotfix = "HF-960961";
}
else audit(AUDIT_INST_VER_NOT_VULN, version);

if (ver_compare(ver:version, fix:max, strict:FALSE) <= 0)
{
  if (report_paranoia > 1 && !isnull(hotfixes) && hotfix >!< hotfixes) vuln = TRUE;
  else
  {
    hotfix_int = int(hotfix - "HF-");
    if (max_hotfix < hotfix_int) vuln = TRUE;
  }
}

if (vuln)
{
  port = 0;

  if (report_verbosity > 0)
  {
    report = '\n' + app_name + ' ' + version + ' is missing patch ' + hotfix + '.\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port:port);
  exit(0);
}
else audit(AUDIT_PATCH_INSTALLED, hotfix + " or later");
