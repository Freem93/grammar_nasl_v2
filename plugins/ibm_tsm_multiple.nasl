#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25662);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2014/08/12 14:36:12 $");
 script_cve_id("CVE-2006-5855");
 script_bugtraq_id(21440);
 script_osvdb_id(31764, 31765, 31766);

 script_name(english:"IBM Tivoli Storage Manager Multiple Remote Overflows");
 script_summary(english:"Test the IBM TSM buffer overflows.");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application that is affected by multiple
remote overflow vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of IBM Tivoli Storage Manager
that is vulnerable to multiple buffer overflows. Using specially a
crafted packet, an attacker could exploit these flaws to execute
arbitrary code on the host or to disable this service.");

 script_set_attribute(attribute:"see_also", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-06-14");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Tivoli Storage Manager 5.2.9 / 5.3.4 or later. Upgrade to
Tivoli Storage Manager Express 5.3.7.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/04");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/12/04");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/03");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");

 script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

 script_dependencies("ibm_tsm_detect.nasl");
 script_require_keys("installed_sw/IBM Tivoli Storage Manager");
 script_require_ports("Services/tsm-agent");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

port = get_service(svc:"tsm-agent",exit_on_fail:TRUE);
prod = "IBM Tivoli Storage Manager";
get_install_count(app_name:prod, exit_if_zero:TRUE);
install = get_single_install(app_name:prod, port:port);

# Install data
version = install["version"];

# Report info
fix = "5.2.9 / 5.3.4";
if(install["Express"]) {
	prod += " Express";
	fix = "5.3.7.1";
}

if(
	(ver_compare(ver:version,fix:"5.2.9",strict:FALSE)   < 0)                         ||
	(version =~ "^5\.3\." && ver_compare(ver:version,fix:"5.3.4",strict:FALSE)   < 0) ||
	(install["Express"]   && ver_compare(ver:version,fix:"5.3.7.1",strict:FALSE) < 0)
)
{
  if(report_verbosity > 0)
  {
    report =
      '\n  Product           : ' + prod +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
      security_hole(port:port,extra:report);
  } else security_hole(port);
} else audit(AUDIT_LISTEN_NOT_VULN, prod, port);
