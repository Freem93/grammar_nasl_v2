#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31121);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2008-0620", "CVE-2008-0621");
  script_bugtraq_id(27613);
  script_osvdb_id(41126, 41127);
  script_xref(name:"Secunia", value:"28786");

  script_name(english:"SAPlpd < 6.29 Multiple Vulnerabilities");
  script_summary(english:"Queries SAPlpd for its version"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote print service is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"SAPlpd, a component of SAP GUI, is running on the remote host. 

According to its version number, the installation of SAPlpd running on
the remote host is affected by several denial of service and buffer
overflow vulnerabilities.  An unauthenticated, remote attacker can
leverage these issues to crash the affected service or to execute
arbitrary code on the affected host subject to the privileges under
which it operates." );
 script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/saplpdz-adv.txt" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Feb/27" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Feb/34" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SAPlpd version 6.29 or later by updating to SAP GUI for
Windows version 7.10 Patchlevel 6 / 6.30 Patchlevel 30 / 6.20
Patchlevel 72 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'SAP SAPLPD 6.28 Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/20");
 script_cvs_date("$Date: 2016/11/02 14:37:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:sap:saplpd");
script_set_attribute(attribute:"cpe",value:"cpe:/a:sap:sapgui");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("lpd_detect.nasl");
  script_require_ports("Services/lpd", 515);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");


port = get_kb_item("Services/lpd");
if (!port) port = 515;
if (!get_port_state(port)) exit(0);


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Query its version number.
req = mkbyte(4) + mkbyte(12) + 'TOB' + '\n';
send(socket:soc, data:req);
res = recv_line(socket:soc, length:1024);
close(soc);

if (strlen(res) && "This is SAPLPD (Version " >< res)
{
  version = strstr(res, "SAPLPD (Version ") - "SAPLPD (Version ";
  if (version) version = version - strstr(version, ")");

  if (version =~ "^[0-9][0-9.]+[0-9]$")
  {
    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # There's a problem if it's before 6.29.
    if (
      ver[0] < 6 ||
      (ver[0] == 6 && ver[1] < 29)
    )
    {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "The remote LPD daemon identifies itself as :\n",
          "\n",
          "  ", res, "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
    }
  }
}
