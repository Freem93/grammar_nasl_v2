#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25702);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_cve_id(
    "CVE-2006-5271",
    "CVE-2006-5272",
    "CVE-2006-5273",
    "CVE-2006-5274"
  );
  script_bugtraq_id(24863);
  script_osvdb_id(
    36098,
    36099,
    36100,
    36101
  );

  script_name(english:"McAfee Common Management Agent < 3.6.0.546 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of McAfee CMA.");

  script_set_attribute(attribute:"synopsis", value:
"A security management service running on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The McAfee Common Management Agent (CMA) running on the remote host
is prior to version 3.6.0 Patch 1 (3.6.0.546). It is, therefore,
affected by multiple vulnerabilities :

  - An integer underflow condition exists that allows an
    unauthenticated, remote attacker to execute arbitrary
    code via a specially crafted UDP packet. (CVE-2006-5271)

  - A stack-based buffer overflow condition exists due to
    improper checking of boundary limits when receiving ping
    packets. An unauthenticated, remote attacker can exploit
    this, via a specially crafted packet, to cause a denial
    of service condition or the execution of arbitrary code.
    (CVE-2006-5272)

  - A heap buffer overflow condition exists due to improper
    checking of bounds when receiving certain packets. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted packet, to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2006-5273)

  - An integer overflow condition exists in the CMA
    Framework service that allows an unauthenticated, remote
    attacker to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2006-5274)");
  script_set_attribute(attribute:"see_also", value:"http://www.iss.net/threats/269.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Common Management Agent version 3.6.0 Patch 1
(3.6.0.546) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:common_management_agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_cma_detect.nasl");
  script_require_ports("Services/www", 8081);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:8081, embedded: 1);
appname = "McAfee Agent";

install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);
ver = install['version'];

ver_fields = split(ver, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);
update = int(ver_fields[3]);

fix = '';

# There's a problem if the version is under 3.6.0.546.
if (major < 3 ||
   (major == 3 && minor < 6) ||
   (major == 3 && minor == 6 && rev == 0 && update < 546))
  fix = '3.6.0.546';

if(fix != '')
{

  report =
    '\n  Installed Version : ' + ver +
    '\n  Fixed Version     : ' + fix + '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);

}
else audit(AUDIT_LISTEN_NOT_VULN, "McAfee Common Management Agent", port, ver);
