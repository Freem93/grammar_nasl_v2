#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72281);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/02/04 18:43:11 $");

  script_cve_id("CVE-2014-1252");
  script_bugtraq_id(65113);
  script_osvdb_id(102460);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-01-23-1");

  script_name(english:"Apple Pages < 2.1 / 5.1 Microsoft Word Document Handling Double Free Arbitrary Code Execution");
  script_summary(english:"Check the version of Pages");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application on the remote host could allow arbitrary code
execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the Apple Pages install
on the remote Mac OS X host reportedly has a double-free issue in its
handling of Microsoft Word documents that could lead to unexpected
program termination or arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6117");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Pages 2.1 / 5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:pages");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("macosx_pages_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Pages/Installed");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/MacOSX/Version")) audit(AUDIT_OS_NOT, "Mac OS X");


get_kb_item_or_exit("MacOSX/Pages/Installed");
list = get_kb_list_or_exit("MacOSX/Pages/*/Version", exit_code:1);

item = branch(keys(list));
path = item - 'MacOSX/Pages' - '/Version';
version = get_kb_item_or_exit(item, exit_code:1);

if (
  version =~ "^1\." ||
  (version =~ "^2\." && ver_compare(ver:version, fix:"2.1", strict:FALSE) == -1) ||
  version =~ "^[34]\." ||
  (version =~ "^5\." && ver_compare(ver:version, fix:"5.1", strict:FALSE) == -1)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.1 / 5.1' +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Apple Pages", version, path);
