#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73498);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/03 20:48:27 $");

  script_cve_id("CVE-2014-3976");
  script_bugtraq_id(66588);
  script_osvdb_id(105354);
  script_xref(name:"EDB-ID", value:"32702");

  script_name(english:"A10 Networks Remote Buffer Overflow");
  script_summary(english:"Checks version of ACOS running on device");

  script_set_attribute(attribute:"synopsis", value:
"The remote A10 appliance is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the self reported version of the remote A10 appliance, it
is affected by a remote buffer overflow vulnerability. By sending a
specially crafted HTTP request, it may be possible to execute
arbitrary code or trigger a denial service condition.");
  script_set_attribute(attribute:"see_also", value:"http://www.quantumleap.it/a10-networks-remote-buffer-overflow-softax/");
  script_set_attribute(attribute:"solution", value:"Upgrade to software version 2.7.0-P6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:a10networks:advanced_core_operating_system");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("a10_acos_detect.nbin");
  script_require_keys("A10/ACOS");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# converts version string to something we can use in ver_compare
# e.g.
# 2.6.1-P1 -> 2.6.1.0.1
# 2.6.1-GR1-P4 -> 2.6.1.1.4
# 2.8.1 -> 2.8.1.0.0
# returns NULL on parse error
function convert_version(version_str)
{
  local_var item, retval;
  retval = '';

  # check that version string conforms to our expectations to avoid
  # false any potential false positives
  if (version_str !~ ("^[0-9]+\.[0-9]+\.[0-9]" +
                      "(\-[pP][0-9]+|" +
                      "\-[gG][rR][0-9]+|" +
                      "\-[gG][rR][0-9]+\-[pP][0-9]+)?$"))
    return NULL;
  item = eregmatch(pattern:"^([0-9.]+)($|[^0-9.])", string:version_str);
  if (isnull(item)) return NULL;

  retval += item[1] + '.';

  item = eregmatch(pattern:"-[gG][rR]([0-9]+)($|[^0-9])", string:version_str);
  if (isnull(item)) retval += '0.';
  else retval += item[1] + '.';

  item = eregmatch(pattern:"-[pP]([0-9]+)($|[^0-9])", string:version_str);
  if (isnull(item)) retval += '0';
  else retval += item[1];

  return retval;
}

get_kb_item_or_exit("A10/ACOS");

version = get_kb_item_or_exit("Host/A10_ACOS/version");

report = '';

fix_str = "2.7.0-P6";
fix = "2.7.0.0.6";

ver = convert_version(version_str:version);
if (isnull(ver)) exit(1, "Error parsing version string '" + version + "'.");

if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fix_str + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "A10 Networks Advanced Core OS", version);
