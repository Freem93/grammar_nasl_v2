#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43615);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2009-4440",
                "CVE-2009-4441", 
                "CVE-2009-4442", 
                "CVE-2009-4443");
  script_bugtraq_id(37481);
  script_osvdb_id(61373, 61374, 61375, 61417);
  script_xref(name:"Secunia", value:"37915");

  script_name(english:"Sun Java System Directory Proxy Server 6.x < 6.3.1.1 Multiple Vulnerabilities.");
  script_summary(english:"Checks the version of Sun Java System Directory Proxy Server");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote directory service is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running the Sun Java System Directory Proxy
Server, an LDAP application-layer protocol gateway.  It is typically
provided with Sun Java System Directory Server Enterprise Edition. 

The installed version of Sun Java System Directory Proxy Server is
older than 6.3.1.1 and thus affected by multiple flaws :

  - Under certain conditions, simultaneous long binds are
    incorrectly assigned the same back-end connection. An
    attacker may exploit this vulnerability to hijack
    an authenticated user's session and perform unauthorized
    operations. (CVE-2009-4440)
 
  - 'SO_KEEPALIVE' socket option is not enabled, making it
    possible for a remote attacker to trigger a denial of
    service condition by exhausting available connection
    slots. (CVE-2009-4441)
 
  - 'max-client-connections' configuration setting is not 
    correctly implemented, making it possible for a remote
    attacker to trigger a denial of service condition.
    (CVE-2009-4442)

  - An unspecified vulnerability in 'psearch' functionality
    may allow an attacker to trigger a denial of service
    condition. (CVE-2009-4443)"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:
"http://download.oracle.com/sunalerts/1021100.1.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to Sun Java System Directory Server Enterprise Edition version 6.3.1 
and then install patch 141958-01 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 362);
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/12/23"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/12/23"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/12/30"
  );
 script_cvs_date("$Date: 2016/12/14 20:33:27 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("ldap_search.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}

include("global_settings.inc");

port = get_kb_item("Services/ldap");
if (isnull(port)) port = 389;
if (!get_port_state(port))  exit(1, "Port "+port+" is not open.");

vendor = get_kb_item("LDAP/" +port+"/vendorName");
if (!vendor)exit(1,"The 'LDAP/"+port+ "/vendorName' KB is missing.");
if ("Sun Microsystems" >!< vendor) exit(0, "The directory server on port "+ port +" is not from Sun Microsystems.");

ver = get_kb_item("LDAP/" + port + "/vendorVersion");
if (!ver) exit(1,"The 'LDAP/"+port+ "/vendorVersion' KB is missing.");
if ("Directory Proxy Server" >!< ver) exit(0, "The directory server on port "+ port + " is '"+ver+"', not Directory Proxy Server.");

if (ereg(pattern:"^Directory Proxy Server 6.([0-2]($|[^0-9])|3($|\.0($|[^0-9])|\.1($|[^.0-9])))",string:ver))
{
  if (report_verbosity > 0)
  {  
    ver = ver - "Directory Proxy Server ";
  
    report = '\n' +
      'Directory Proxy Server version ' + ver + ' is installed on' + '\n' +
      'the remote host.' + '\n' ;
     security_warning(port:port, extra:report);
  }
  else 
   security_warning(port);
  
   exit(0);
}
else
  exit(0,"'"+ ver + "' on port " + port +" from " + vendor + " is installed and not vulnerable.");
