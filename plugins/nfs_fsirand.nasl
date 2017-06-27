#
# (C) Tenable Network Security, Inc.
#

# This is a _very_ old flaw

include("compat.inc");

if (description)
{
  script_id(11353);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/02/19 01:34:32 $");

  script_cve_id("CVE-1999-0167");
  script_bugtraq_id(32);
  script_osvdb_id(889);
  script_xref(name:"CERT-CC", value:"CA-1991-21");

  script_name(english:"NFS Predictable Filehandles Filesystem Access");
  script_summary(english:"Checks for NFS");

  script_set_attribute(attribute:'synopsis', value:'The remote service is vulnerable to access control breach.');
  script_set_attribute(
    attribute:'description',
    value:
"The remote NFS server might allow an attacker to guess the NFS
filehandles, and therefore allow them to mount the remote filesystems
without the proper authorizations."
  );
  script_set_attribute(attribute:'solution', value:"Contact your vendor for the appropriate patches.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"1991/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
  script_family(english:"RPC");
  script_dependencie("rpc_portmap.nasl", "os_fingerprint.nasl");
  script_require_keys("rpc/portmap", "Host/OS");
  exit(0);
}



include("global_settings.inc");
include("misc_func.inc");
include("sunrpc_func.inc");

os = get_kb_item_or_exit("Host/OS");
if ("Solaris 2.4" >!< os) exit(0, "The host is not running Solaris 2.4.");

#----------------------------------------------------------------------------#
#                              Here we go                                    #
#----------------------------------------------------------------------------#

security_problem = 0;
list = "";
number_of_shares = 0;
port = get_rpc_port2(program:100005, protocol:IPPROTO_TCP);
soc = 0;
if(!port)
{
 port = get_rpc_port2(program:100005, protocol:IPPROTO_UDP);
 if (!port) exit(0, "The host is not affected.");
}

security_warning(port);
