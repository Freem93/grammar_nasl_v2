#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24240);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/04/28 14:01:58 $");

  script_cve_id("CVE-2007-0449", "CVE-2007-0672", "CVE-2007-0673");
  script_bugtraq_id(22199, 22337, 22339, 22340, 22342);
  script_osvdb_id(31593, 32948, 32949);

  script_name(english:"CA BrightStor ARCserve Backup for Laptops & Desktops Server Multiple Vulnerabilities (QO83833)");
  script_summary(english:"Checks version of BrightStor ARCserve Backup for Laptops & Desktops Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote backup server software is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of BrightStor ARCserve
Backup for Laptops & Desktops Server on the remote host is affected by
multiple buffer overflows and denial of service vulnerabilities that
can be exploited by a remote attacker to execute arbitrary code on the
affected host with LOCAL SYSTEM privileges or to crash the associated
services.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Jan/682");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Jan/683");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Jan/685");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Jan/686");
  # https://web.archive.org/web/20070206063608/http://supportconnectw.ca.com/public/sams/lifeguard/infodocs/babldimpsec-notice.asp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4ee8257");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as described in the vendor advisory
referenced above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CA BrightStor ARCserve for Laptops and Desktops LGServer Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:brightstor_arcserve_backup_laptops_desktops");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("arcserve_lgserver_admin_detect.nasl");
  script_require_keys("ARCSERVE/LGServer/Version");

  exit(0);
}


ver = get_kb_item("ARCSERVE/LGServer/Version");
if (isnull(ver)) exit(0);


matches = eregmatch(string:ver, pattern:"^([0-9]+\.[0-9]+)\.([0-9]+)$");
if (!isnull(matches))
{
  ver = matches[1];
  build = int(matches[2]);

  if (
    (ver == "11.1" && build < 900) ||
    # nb: QI85497 says there's no patch for 11.0; the solution is to 
    #     upgrade to 11.1 and then apply BABLD r11.1 SP2.
    (ver == "11.0") ||
    # nb: QO85402 doesn't exist.
    (ver == "4.0")
  )
  {
    # Issue a report for each open port used by the server.
    port = get_kb_item("Services/lgserver");
    if (port && get_tcp_port_state(port)) security_hole(port);

    port = get_kb_item("Services/lgserver_admin");
    if (port && get_tcp_port_state(port)) security_hole(port);
  }
}
