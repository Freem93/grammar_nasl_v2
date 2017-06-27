#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81669);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_cve_id("CVE-2015-2157");
  script_bugtraq_id(72825);
  script_osvdb_id(118932, 136167);

  script_name(english:"PuTTY < 0.64 Multiple Information Disclosure Vulnerabilities");
  script_summary(english:"Checks the version of PuTTY.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an SSH client that is affected by multiple
information disclosure vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of PuTTY installed that is prior to
0.64. It is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists due to a
    failure to clear SSH-2 private key information from the
    memory during the saving or loading of key files to
    disk. A local attacker can exploit this to disclose
    potentially sensitive information. (CVE-2015-2157)

  - An information disclose vulnerability exists in the
    Diffie-Hellman Key Exchange due to a failure to properly
    handle 0 value keys sent by the server. A
    man-in-the-middle attacker can exploit this to disclose
    potentially sensitive information. (VulnDB 136167)");
  # http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/private-key-not-wiped-2.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df5e80bf");
  # http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/diffie-hellman-range-check.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82c8b79b");
  script_set_attribute(attribute:"see_also", value:"http://www.chiark.greenend.org.uk/~sgtatham/putty/changes.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to PuTTY version 0.64 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:simon_tatham:putty");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("putty_installed.nasl");
  script_require_keys("installed_sw/PuTTY");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'PuTTY';

# Pull the installation information from the KB.
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

base = install['path'];
ver = install['version'];
num = install['VersionNumber'];

# Check if the installed version is vulnerable.
# Affected version < 0.64
fix = "0.64.0.0";
if (ver_compare(ver:num, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + base +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, base);
