#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89724);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_osvdb_id(
    134606,
    134607
  );

  script_name(english:"FireEye Operating System Multiple Vulnerabilities");
  script_summary(english:"Checks the version of FEOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FireEye Operating System
(FEOS) that is missing a vendor-supplied security patch. It is,
therefore, affected by multiple vulnerabilities :

  - An flaw exists in the Virtual Execution Engine (VXE)
    during the handling of file names that were previously
    flagged for the whitelist. A remote attacker can exploit
    this, via subsequent malicious files with the same file
    name, to bypass the analysis engine. (VulnDB 134606)

  - A flaw exists when handling a specially crafted URL that
    allows an authenticated, remote attacker to render
    plaintext in the web user interface post-authentication,
    resulting in the disclosure of sensitive information.
    (VulnDB 134607)

  NOTE: FX version 7.5.0 is affected by the Analysis Engine Evasion
  vulnerability, but NOT the URL Encoded Bypass vulnerability.
");
  # https://www.fireeye.com/content/dam/fireeye-www/support/pdfs/2015-q4-security-vulnerability-advisory.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab6d5aa8");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fireeye:feos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("fireeye_os_version.nbin");
  script_require_keys("Host/FireEye/series", "Host/FireEye/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "FireEye OS";
series = get_kb_item_or_exit("Host/FireEye/series");
version = get_kb_item_or_exit("Host/FireEye/version");
#CM < 7.5.0 but report fix as 7.6.2
#FX < 7.5.1 but 7.5.0 wouldnt be affected by the url encoded vuln

if (series == "NX") fix = "7.6.1";
else if (series == "EX") fix = "7.6.2";
else if (series == "FX") fix = "7.5.1";
else if (series == "AX") fix = "7.7.0";
else if (series == "CM") { fix = "7.5.0"; rptFix = "7.6.2"; }
else audit(AUDIT_DEVICE_NOT_VULN, "FireEye "+series);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = 0;
  if (empty_or_null(rptFix)) rptFix = fix;
  report =
      '\n  Series            : ' + series +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + rptFix +
      '\n';

  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    extra      : report
  );
  exit(0);
}
else audit(AUDIT_DEVICE_NOT_VULN, "FireEye "+series, version);
