#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83352);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/08/18 13:35:59 $");

  script_cve_id(
      "CVE-2015-2170",
      "CVE-2015-2221", 
      "CVE-2015-2222", 
      "CVE-2015-2305", 
      "CVE-2015-2668"
  );
  script_bugtraq_id(
    72611,
    72611,
    74472
  );
  script_osvdb_id(
    118433,
    121476,
    121477,
    121478,
    121479
  );
  script_xref(name:"CERT", value:"695940");

  script_name(english:"ClamAV < 0.98.7 Multiple Vulnerabilities");
  script_summary(english:"Checks the response to a clamd VERSION command.");

  script_set_attribute(attribute:"synopsis", value:
"The antivirus service running on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the ClamAV clamd antivirus daemon on the
remote host is prior to 0.98.7. It is, therefore, affected
by multiple vulnerabilities :

  - An unspecified flaw exists in the pefromupx() function
    in upx.c. A remote attacker can exploit this flaw, via a
    specially crafted file, to crash the application.
    (CVE-2015-2170)

  - An unspecified flaw exists in the yc_poly_emulator()
    function in yc.c. A remote attacker can exploit this
    flaw, via a specially crafted y0da cryptor file, to
    cause an infinite loop and application hang.
    (CVE-2015-2221)

  - An unspecified flaw exists in the cli_scanpe() function
    in pe.c. A remote attacker can exploit this, via a
    specially crafted petite packer file, to crash the
    program. (CVE-2015-2222)

  - An integer overflow condition exists in the bundled
    Henry Spencer regex library in the regcomp() function in
    regcomp.c due to improper validation of user-supplied
    input. A remote attacker can exploit this to cause a
    buffer overflow, resulting in a denial of service or the
    execution of arbitrary code. (CVE-2015-2305)

  - An unspecified flaw exists when handling specially
    crafted xz archive files. A remote attacker can exploit
    this to cause an infinite loop. (CVE-2015-2668)");
  # Release blog
  script_set_attribute(attribute:"see_also", value:"http://blog.clamav.net/2015/04/clamav-0987-has-been-released.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ClamAV 0.98.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:clamav:clamav");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("clamav_detect.nasl");
  script_require_keys("Antivirus/ClamAV/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Antivirus/ClamAV/version");
port = get_service(svc:"clamd", default:3310, exit_on_fail:TRUE);

# nb: banner checks of open source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Check the version number.
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Affected :
# 0.x < 0.98.7
# 0.98.7beta\d
# 0.98.7rc\d
if (
  (ver[0] == 0 && ver[1] < 98) ||
  (ver[0] == 0 && ver[1] == 98 && ver[2] < 7) ||
  version =~ "^0\.98\.7-(beta|rc)\d($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 0.98.7' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "ClamAV", port, version);
