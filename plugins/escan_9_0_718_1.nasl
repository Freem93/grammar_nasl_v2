#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25296);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2007-2687");
  script_bugtraq_id(24112);
  script_osvdb_id(36580);

  script_name(english:"eScan < 9.0.718.1 MicroWorld Agent service (MWAGENT.EXE) Command Decryption Overflow");
  script_summary(english:"Checks version number of eScan");

 script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the installation of eScan on the
remote host includes a service, the MicroWorld Agent service, for
remote administration that fails to properly handle overly-long
commands.  A remote attacker can leverage this issue to crash the
service or even execute arbitrary code. 

Since the service operates with LocalSystem privileges, successful
exploitation could lead to a complete compromise of the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2007-54/advisory/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to eScan version 9.0.718.1 or later as that reportedly
resolves the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/23");
 script_cvs_date("$Date: 2011/03/21 01:21:16 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

  if ( NASL_LEVEL >= 3000 )
  	script_dependencies("escan_detect.nbin");
  script_require_keys("eScan/Version");
  script_require_ports("Services/mwagent", 2222);

  exit(0);
}


if ( NASL_LEVEL < 3000 ) exit(0);
port = get_kb_item("Services/mwagent");
if (!port) port = 2222;
if (!get_port_state(port)) exit(0);


ver = get_kb_item("eScan/Version");
if (isnull(ver)) exit(0);

iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
  iver[i] = int(iver[i]);


if (
  iver[0] < 9 ||
  (
    iver[0] == 9 && iver[1] == 0 &&
    (
      iver[2] < 718 ||
      (iver[2] == 718 && iver[3] < 1)
    )
  )
) 
{
  report = string(
    "eScan version ", ver, " is currently installed on the remote host.\n"
  );
  security_hole(port:port, extra:report);
}
