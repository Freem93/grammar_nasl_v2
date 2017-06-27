#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57365);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_cve_id("CVE-2011-4607");
  script_bugtraq_id(51021);
  script_osvdb_id(82593);

  script_name(english:"PuTTY Password Local Information Disclosure");
  script_summary(english:"Checks the version of PuTTY.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an SSH client that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has an installation of PuTTY between 0.59 and 0.61,
inclusive.  Such versions are known to contain an information
disclosure issue, where PuTTY neglects to wipe passwords from memory
that it no longer requires. 

Note that to exploit this vulnerability, a malicious, local process
must have permission to access the memory assigned to the PuTTY
process.");

  script_set_attribute(attribute:"solution", value:"Upgrade to PuTTY version 0.62.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  # http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/password-not-wiped.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d29e474b");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:simon_tatham:putty");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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
start = "0.59.0.0";
fix = "0.62.0.0";

if (ver_compare(ver:num, fix:start) < 0 || ver_compare(ver:num, fix:fix) >= 0)
  audit(AUDIT_INST_PATH_NOT_VULN, app, ver, base);

# Report findings.
port = get_kb_item("SMB/transport");
if (isnull(port)) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + base +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
