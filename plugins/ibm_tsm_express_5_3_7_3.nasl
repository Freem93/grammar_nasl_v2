#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29997);
  script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");

  script_cve_id("CVE-2008-0247");
  script_bugtraq_id(27235);
  script_osvdb_id(40353);

  script_name(english:"IBM Tivoli Storage Manager Express Backup Server Service (dsmsvc.exe) Packet Handling Remote Overflow");
  script_summary(english:"Checks the version of TSM Express.");

 script_set_attribute(attribute:"synopsis", value:"The remote backup service is affected by a buffer overflow issue.");
 script_set_attribute(attribute:"description", value:
"The version of Tivoli Storage Manager (TSM) Express installed on the
remote host is prior to 5.3.7.3. It is, therefore, affected by a
heap-based buffer overflow vulnerability that can be triggered by a
user-supplied length value. This could allow an unauthenticated
attacker to run arbitrary code on the host with SYSTEM privileges.");
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-001.html");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Jan/227" );
 script_set_attribute(attribute:"see_also", value:"http://securitytracker.com/id?1019182" );
 script_set_attribute(attribute:"solution", value:"Upgrade to TSM Express 5.3.7.3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"patch_publication_date", value:"2008/01/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/17");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager_express");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

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

# Only the express version is vulnerable
if(!install["Express"]) audit(AUDIT_LISTEN_NOT_VULN, prod, port);

fix = "5.3.7.3";
if(ver_compare(ver:version,fix:fix,strict:FALSE) < 0)
{
  if(report_verbosity > 0)
  {
    report =
      '\n  Product           : ' + prod + " Express" +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
      security_hole(port:port,extra:report);
  } else security_hole(port);
} else audit(AUDIT_LISTEN_NOT_VULN, prod, port);
