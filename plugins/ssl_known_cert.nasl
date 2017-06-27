#TRUSTED 3073770e880e2727f101131c34458039317c19cd60dbe7626cefeb653e74d3a4d490d3fc38a98cd8472a7c8714fc5573a0cfc45a4c93e015cc84efab2912e6d5ba8e46e469b026df3aaaa2219016c08c202582809eefb3cab33a2d64edd694a0530ef3771e2476dd9fdca914ec146af2f4de066a1bca3a597084a816c4ccf81d8ad7bc2811918f34c4fc8bd2865d34e5104193fa2ed53f7d8307e4504a1a56f08515116c6764a5cfb7fd216a9e3f0b6d11b8f4b2494d4eab52a410440e885cdfa337acd244b0fbb60332ae885ed63dbc693e3222f292c87626509cb4fdb30da7097fab9d00070e69e44d33daef63ce3e6314f1f97ab9a9c24ab647ed205fb337d38a02a9459876707d73311ec399098d2c593b2f9d53f8ce282297b66df43f9041bb24cf628b9cd0d32dd64e29f0d846a217fc33c4475cd7c138a8aa145872b01f6d925c869c52657291fa78fbed34e39de9c4eec2f94aea1f8e983ef3d8bb9e48f030e274ee1c1d5292c3d94dbb635509dfbb2f1ffd2bcc97538bbf202100dae4623c3db263782719e628aa6639a78e40faa9c6bff802f573a311a9343e0ecc50afa89f7d37187ef7b587a23c2dc8e56672737885a284829e8170fc3a718db1e7b6ef79b583f707c7e30902a0fe938abf70c334ffbf9e17cab6e4b55482cf2e3f0429c510f3f92bca49b55a038b9a3968900a0b07c113e8502c660be08e0dde
#
# (C) Tenable Network Security, Inc.
#


if ( NASL_LEVEL < 3208 ) exit(0);

include("compat.inc");

if(description)
{
 script_id(51356);
 script_version("1.8");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/08/07");
 
 script_name(english: "Well-known SSL Certificate Used in Remote Device");
 script_summary(english: "Checks SHA1 fingerprint.");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service is using a well-known SSL certificate whose private
key has been published.");
 script_set_attribute(attribute:"description", value:
"The X.509 certificate of the remote host is known to be shipping by
default with the remote service / device.  The private key for this
cert has been published, therefore the SSL communications done with
the remote host can not be considered as being secret as anyone with
the ability to snoop the traffic between the remote host and the
clients could decipher the traffic.");
 script_set_attribute(attribute:"solution", value:
"Purchase or generate a proper certificate for this service and
replace it, or ask your vendor for a way to do so.");
 script_set_attribute(attribute:"see_also", value: "http://www.devttys0.com/2010/12/breaking-ssl-on-embedded-devices/");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/21");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");
 script_family(english: "General");

 script_dependencies("ssl_supported_versions.nasl");
 script_require_keys("SSL/Supported");

 exit(0);
}


include("global_settings.inc");
include("x509_func.inc");


get_kb_item_or_exit("SSL/Supported");

# Get list of ports that use SSL or StartTLS.
ports = get_ssl_ports();
if (isnull(ports) || max_index(ports) == 0)
  exit(1, "The host does not appear to have any SSL-based services.");

if ( file_stat("ssl_known_cert.inc") <= 0 ) exit(1, "Could not find the list of certificates.");
known_certs = fread("ssl_known_cert.inc");
if ( isnull(known_certs) ) exit(1, "Could not load the list of certificates.");


foreach port ( ports )
{
 cert = get_server_cert(port:port, encoding:"der");
 if ( isnull(cert) )  continue;
 sha1 = toupper(hexstr(SHA1(cert)));
 digest = "";
 for ( i = 0 ; i < strlen(sha1) ; i += 2 )
  digest = strcat(digest, sha1[i], sha1[i+1], ":");

 digest = substr(digest, 0, strlen(digest) - 2 );
 line = egrep(pattern:"^#" + digest, string:known_certs);
 if ( strlen(line) > 0  ) 
 {
  array = split(line, sep:'|', keep:FALSE);
  security_warning(port:port, extra:'
The remote SSL certificate has the following SHA1 fingerprint :

' + digest + '

This certificate is known to be used in the following device :
' + array[1] + ' ' + array[2] + ' ' + array[3] + ' ' + array[4] + '\n');
 }
}
