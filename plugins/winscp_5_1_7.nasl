#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72389);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/10/07 19:48:35 $");

  script_cve_id("CVE-2013-4206", "CVE-2013-4207", "CVE-2013-4208");
  script_bugtraq_id(61644, 61645, 61649);
  script_osvdb_id(96080, 96081, 96210);

  script_name(english:"WinSCP < 5.1.7 Multiple Vulnerabilities");
  script_summary(english:"Checks version of WinSCP.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The WinSCP program installed on the remote host is a version prior to
5.1.7. It therefore contains code from PuTTY that is affected by the
following vulnerabilities related to PuTTY :

  - An overflow error exists that allows heap corruption
    when handling DSA signatures. (CVE-2013-4206)

  - A buffer overflow error exists related to modular
    inverse calculation, non-coprime values, and DSA
    signature verification. (CVE-2013-4207)

  - An error exists that allows disclosure of private key
    material. (CVE-2013-4208)");
  script_set_attribute(attribute:"see_also", value:"http://winscp.net/tracker/show_bug.cgi?id=1039");
  script_set_attribute(attribute:"see_also", value:"http://winscp.net/eng/docs/history#5.1.7");
  # http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-modmul.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20c27652");
  # http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-bignum-division-by-zero.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1b0243c");
  # http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/private-key-not-wiped.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7bdd07a8");
  script_set_attribute(attribute:"solution", value:"Upgrade to WinSCP version 5.1.7 / 5.2.4 beta or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:winscp:winscp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("winscp_installed.nbin");
  script_require_keys("installed_sw/WinSCP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'WinSCP';
fixed_version = '5.1.7 / 5.2.4 beta (5.2.4.3548)';

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

version = install['version'];
path = install['path'];

if (
  # < 5.1.7
  ver_compare(ver:version, fix:"5.1.7", strict:FALSE) < 0 ||
  # 5.2.x
  (version =~ "^5\.2\." && ver_compare(ver:version, fix:"5.2.4.3548", strict:FALSE) < 0)
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed versions    : ' + fixed_version + 
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
