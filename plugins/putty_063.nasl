#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69318);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/20 14:30:35 $");

  script_cve_id(
    "CVE-2013-4206",
    "CVE-2013-4207",
    "CVE-2013-4208",
    "CVE-2013-4852"
  );
  script_bugtraq_id(61599, 61644, 61645, 61649);
  script_osvdb_id(95970, 96080, 96081, 96210);

  script_name(english:"PuTTY 0.52 to 0.62 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PuTTY.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an SSH client that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has an installation of PuTTY version 0.52 or greater
but earlier than version 0.63.  As such, it is reportedly affected by
the following vulnerabilities :

  - An overflow error exists in the function 'modmul' in
    the file 'putty/sshbn.c' that could allow heap
    corruption when handling DSA signatures. (CVE-2013-4206)

  - A buffer overflow error exists related to modular
    inverse calculation, non-coprime values and DSA
    signature verification. (CVE-2013-4207)

  - An error exists in the file 'putty/sshdss.c' that could
    allow disclosure of private key material.
    (CVE-2013-4208)

  - Multiple overflow errors exist in the files 'sshrsa.c'
    and 'sshdss.c'. (CVE-2013-4852)");
  # http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-signature-stringlen.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4834e145");
  # http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-modmul.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20c27652");
  # http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/private-key-not-wiped.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7bdd07a8");
  # http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-bignum-division-by-zero.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1b0243c");
  script_set_attribute(attribute:"see_also", value:"http://www.search-lab.hu/advisories/secadv-20130722");

  script_set_attribute(attribute:"solution", value:"Upgrade to PuTTY version 0.63 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:simon_tatham:putty");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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
# Affected 0.52 >= version < 0.63
lower_vuln_boundary = "0.52.0.0";
fix = "0.63.0.0";
if (
  (ver_compare(ver:num, fix:lower_vuln_boundary, strict:FALSE) >= 0) &&
  (ver_compare(ver:num, fix:fix, strict:FALSE) < 0)
)
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
