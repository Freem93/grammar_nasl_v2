#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93128);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");

  script_cve_id("CVE-2016-6909");
  script_bugtraq_id(92523);
  script_osvdb_id(143063);
  script_xref(name:"EDB-ID", value:"40276");

  script_name(english:"Fortinet FortiOS 4.1.x < 4.1.11 / 4.2.x < 4.2.13 / 4.3.x < 4.3.9 Web Interface Cookie Parser RCE (EGREGIOUSBLUNDER)");
  script_summary(english:"Checks version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote FortiGate device is running a version of FortiOS that is
4.1.x prior to 4.1.11, 4.2.x prior to 4.2.13, or 4.3.x prior to 4.3.9. 
It is, therefore, affected by a remote code execution vulnerability,
known as EGREGIOUSBLUNDER, in the web interface due to improper
validation when parsing cookies. An unauthenticated, remote attacker
can exploit this, via a specially crafted HTTP request, to cause a
buffer overflow condition, resulting in a denial of service condition
or the execution of arbitrary code. 


EGREGIOUSBLUNDER is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2016/08/14 by a group known as the Shadow
Brokers.");
  script_set_attribute(attribute:"see_also", value:"http://fortiguard.com/advisory/FG-IR-16-023");
  # https://www.riskbasedsecurity.com/2016/08/the-shadow-brokers-lifting-the-shadows-of-the-nsas-equation-group/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c7e0cf3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS 4.1.11 / 4.2.13 / 4.3.9 / 5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/08/14");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/26");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "FortiOS";

version = get_kb_item_or_exit("Host/Fortigate/version");
model = get_kb_item_or_exit("Host/Fortigate/model");

# Make sure device is FortiGate
if (!preg(string:model, pattern:"fortigate", icase:TRUE)) audit(AUDIT_HOST_NOT, "a FortiGate");

if (version =~ "^4\.1\.") fix = "4.1.11";
else if (version =~ "^4\.2\.") fix = "4.2.13";
else if (version =~ "^4\.3\.") fix = "4.3.9";
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  report =
    '\n  Model             : ' + model +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, extra:report, port:0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
