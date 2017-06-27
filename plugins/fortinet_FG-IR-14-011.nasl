#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73669);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/20 14:02:59 $");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_osvdb_id(105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");

  script_name(english:"Fortinet OpenSSL Information Disclosure (Heartbleed)");
  script_summary(english:"Checks version of Fortinet device.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is affected by an information disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The firmware of the remote Fortinet host is running a version of
OpenSSL that is affected by a remote information disclosure,
commonly known as the 'Heartbleed' bug. A remote, unauthenticated,
attacker could potentially exploit this vulnerability to extract up to
64 kilobytes of memory per request from the device."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.fortiguard.com/advisory/FG-IR-14-011");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to a firmware version containing a fix for this
vulnerability as referenced in the vendor advisory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date",value:"2014/04/08");
  script_set_attribute(attribute:"patch_publication_date",value:"2014/04/09");
  script_set_attribute(attribute:"plugin_publication_date",value:"2014/04/11");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Host/Fortigate/build");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

model = get_kb_item_or_exit("Host/Fortigate/model");
version = get_kb_item_or_exit("Host/Fortigate/version");
build = get_kb_item_or_exit("Host/Fortigate/build");

# FortiOS check.
if (preg(string:model, pattern:"forti(gate|wifi)", icase:TRUE))
{
  # Only 5.x is affected.
  if (version =~ "^5\.") fix = "5.0.7";
}
# FortiMail Check
else if (preg(string:model, pattern:"fortimail", icase:TRUE))
{
  # Only 4.3.x and 5.x are affected.
  if (version =~ "^4\.3\.") fix = "4.3.7";
  else if (version =~ "^5\.0\.") fix = "5.0.5";
  else if (version =~ "^5\.1\.") fix = "5.1.2";
}
# FortiRecorder Check, all affected.
else if (preg(string:model, pattern:"fortirecorder", icase:TRUE))
{
  fix = "1.4.1";
}
# FortiVoice check, specific models affected.
else if (preg(string:model, pattern:"fortivoice-(200d|vm)", icase:TRUE))
{
  fix = "3.0.1";
}
# FortiADC, specific models and versions affected.
else if (preg(string:model, pattern:"fortiadc", icase:TRUE))
{
  if (model =~ "E$" && version =~ "^3\.") fix = "3.2.3";
  else if (model =~ "-(15|20|40)00D$") fix = "3.2.2";
}
# FortiDDOS B-Series affected.
else if (preg(string:model, pattern:"fortiddos-\d+B", icase:TRUE))
{
  fix = "4.0.1";
}

if (fix && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = 0;
  if (report_verbosity > 0)
  {
    report =
      '\n  Model        : ' + model +
      '\n  Version      : ' + version +
      '\n  Fixed Version: ' + fix +
      '\n';

    security_hole(extra:report, port:port);
  }
  else security_hole(port:port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, model, version);
