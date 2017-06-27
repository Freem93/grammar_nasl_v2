#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(35308);
 script_version ("$Revision: 1.9 $");

 script_cve_id("CVE-2009-0043");
 script_bugtraq_id(33161);
 script_osvdb_id(51189);

 script_name(english:"TCL Shell (tclsh) Arbitrary Command Execution");
 script_summary(english: "Execute commands through TCLSH");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands can be run on this host." );
 script_set_attribute(attribute:"description", value:
"A TCL shell (tclsh) is running on this port, and it allows
unauthenticated users to run arbitrary commands on the machine." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?513b6d4d" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/499857/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Check that the system has not been compromised and reinstall if
necessary. 

If using a product from Computer Associates, apply the appropriate
patch referenced in the vendor's advisory above.  Otherwise, disable
the service or restrict access to it." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(264);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/01/08");
 script_cvs_date("$Date: 2015/09/24 23:21:21 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl", "find_service2.nasl");
 script_require_ports("Services/unknown");
 script_exclude_keys("global_settings/disable_service_discovery");

 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (get_kb_item("global_settings/disable_service_discovery")) exit(0);


ports = get_kb_list("Services/unknown");
if (isnull(ports)) exit(0);

foreach port (list_uniq(ports))
{
  if (!get_tcp_port_state(port)) continue;
  if (!service_is_unknown(port:port)) continue;

  if (!thorough_tests && report_paranoia < 2)
  {
    banner = get_unknown_banner(port:port, dontfetch:TRUE);
    if (
      !banner || ("HELP" >!< banner && "GET / HTTP/1.0" >!< banner)
    ) continue;
  }

  soc = open_sock_tcp(port);
  if (!soc) continue;

  req = "[array get tcl_platform]";
  send(socket:soc, data:req+'\r\n');
  res = recv(socket:soc, length:4096);
  close(soc);
  if (res == NULL) continue;

  # If we got information about the TCL platform...
  lres = tolower(res);
  if ("platform" >< lres && "byteorder" >< lres && "wordsize" >< lres)
  {
    # Extract it for the report.
    info = "";
    res = ereg_replace(pattern:"{(.*) (.*)}", replace:"\1^!^\2", string:res);
    parts = split(res, sep:" ", keep:FALSE);
    if (max_index(parts) % 2 == 0)
    {
      for (i=0; i<max_index(parts); i+=2)
      {
        key = parts[i];
        key = str_replace(find:"^!^", replace:" ", string:key);
        val = parts[i+1];
        val = str_replace(find:"^!^", replace:" ", string:val);

        info += '  ' + key + crap(data:" ", length:10-strlen(key)) + ' : ' + val + '\n';
      }
    }    

    # Try to run a command.
    output = "";
    soc2 = open_sock_tcp(port);
    if (soc2)
    {
      if ("windows" >< tolower(res)) cmd = "ipconfig /all";
      else cmd = "id";

      req2 = string("[exec ", cmd, "]");
      send(socket:soc2, data:req2+'\r\n');
      res2 = recv(socket:soc2, length:4096);

      if (
        (
          cmd == "id" && 
          egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res2)
        ) ||
        (
          "ipconfig" >< cmd &&
          "Subnet Mask" >< res2
        )
      ) output = res2;

      close(soc2);
    }

    if (report_verbosity && (info || output))
    {
      report = "";
      if (info)
      {
        report = string(
          report,
          "\n",
          "Nessus was able to collect the following information from the remote host :\n",
          "\n",
          info
        );
      }
      if (output)
      {
        report = string(
          report,
          "\n",
          "Nessus was able to execute the command '", cmd, "' on the remote \n",
          "host by sending the following request :\n",
          "\n",
          "  ", req2, "\n",
          "\n",
          "It produced the following output :\n",
          "\n",
          "  ", str_replace(find:'\n', replace:'\n  ', string:output), "\n"
        );
      }

      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    # Register the service.
    register_service(port:port, proto:"wild_tclsh");
  }
}
