#
# (C) Tenable Network Security, Inc.
#


if ( NASL_LEVEL < 3208 ) exit(0);

include("compat.inc");

if(description)
{
 script_id(56043);
 script_version ("$Revision: 1.9 $");
 script_cvs_date("$Date: 2017/05/16 20:53:10 $");
 
 script_name(english: "SSL Certificate Signed with the Revoked DigiNotar Certificate Authority");
 script_summary(english: "Checks that the certificate chain is signed by the DigiNotar authority");
 
 script_set_attribute(attribute:"synopsis", value:
"The SSL certificate for this service was signed by a compromised CA
certificate.");
 script_set_attribute(attribute:"description", value:
"The X.509 certificate of the remote host was signed by a certificate
belonging to a Certificate Authority (CA) called DigiNotar, which was
revoked due to a known compromise.  You should verify that the remote
certificate indeed was obtained legally, and you should get a new CA
to sign it, as most web browsers are being updated to stop trusting
this authority.");
 script_set_attribute(attribute:"solution", value:
"Purchase or generate a new certificate for this service.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3fc8e9a");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?baa49230");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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


global_var certChain;
global_var certProblem;
global_var certProblemIdx;
global_var report;


function load_DigiNotar()
{
 local_var data;
 local_var ret;
 local_var raw;
 local_var r;
 local_var line;
 local_var der;
 local_var inCert;
 local_var n;
 local_var all;

 all = _FCT_ANON_ARGS[0];


 ret = all[0];
 raw = all[1];
 data = "
-----BEGIN CERTIFICATE-----
MIIFijCCA3KgAwIBAgIQDHbanJEMTiye/hXQWJM8TDANBgkqhkiG9w0BAQUFADBf
MQswCQYDVQQGEwJOTDESMBAGA1UEChMJRGlnaU5vdGFyMRowGAYDVQQDExFEaWdp
Tm90YXIgUm9vdCBDQTEgMB4GCSqGSIb3DQEJARYRaW5mb0BkaWdpbm90YXIubmww
HhcNMDcwNTE2MTcxOTM2WhcNMjUwMzMxMTgxOTIxWjBfMQswCQYDVQQGEwJOTDES
MBAGA1UEChMJRGlnaU5vdGFyMRowGAYDVQQDExFEaWdpTm90YXIgUm9vdCBDQTEg
MB4GCSqGSIb3DQEJARYRaW5mb0BkaWdpbm90YXIubmwwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQCssFjBAL3YIQgLK5r+blYwBZ8bd5AQQVzDDYcRd46B
8cp86Yxq7Th0Nbva3/m7wAk3tJZzgX0zGpg595NvlX89ubF1h7pRSOiLcD6VBMXY
tsMW2YiwsYcdcNqGtA8Ui3rPENF0NqISe3eGSnnme98CEWilToauNFibJBN4ViIl
HgGLS1Fx+4LMWZZpiFpoU8W5DQI3y0u8ZkqQfioLBQftFl9VkHXYRskbg+IIvvEj
zJkd1ioPgyAVWCeCLvriIsJJsbkBgWqdbZ1Ad2h2TiEqbYRAhU52mXyC8/O3AlnU
JgEbjt+tUwbRrhjd4rI6y9eIOI6sWym5GdOY+RgDz0iChmYLG2kPyes4iHomGgVM
ktck1JbyrFIto0fVUvY//s6EBnCmqj6i8rZWNBhXouSBbefK8GrTx5FrAoNBfBXv
a5pkXuPQPOWx63tdhvvL5ndJzaNl3Pe5nLjkC1+Tz8wwGjIczhxjlaX56uF0i57p
K6kwe6AYHw4YC+VbqdPRbB4HZ4+RS6mKvNJmqpMBiLKR+jFc1abBUggJzQpjotMi
puih2TkGl/VujQKQjBR7P4DNG5y6xFhyI6+2Vp/GekIzKQc/gsnmHwUNzUwoNovT
yD4cxojvXu6JZOkd69qJfjKmadHdzIif0dDJZiHcBmfFlHqabWJMfczgZICynkeO
owIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNV
HQ4EFgQUiGi/4I41xDs4a2L3KDuEgcgM100wDQYJKoZIhvcNAQEFBQADggIBADsC
jcs8MOhuoK3yc7NfniUTBAXT9uOLuwt5zlPe5JbF0a9zvNXD0EBVfEB/zRtfCdXy
fJ9oHbtdzno5wozWmHvFg1Wo1X1AyuAe94leY12hE8JdiraKfADzI8PthV9xdvBo
Y6pFITlIYXg23PFDk9Qlx/KAZeFTAnVR/Ho67zerhChXDNjU1JlWbOOi/lmEtDHo
M/hklJRRl6s5xUvt2t2AC298KQ3EjopyDedTFLJgQT2EkTFoPSdE2+Xe9PpjRchM
Ppj1P0G6Tss3DbpmmPHdy59c91Q2gmssvBNhl0L4eLvMyKKfyvBovWsdst+Nbwed
2o5nx0ceyrm/KkKRt2NTZvFCo+H0Wk1Ya7XkpDOtXHAd3ODy63MUkZoDweoAZbwH
/M8SESIsrqC9OuCiKthZ6SnTGDWkrBFfGbW1G/8iSlzGeuQX7yCpp/Q/rYqnmgQl
nQ7KN+ZQ/YxCKQSa7LnPS3K94gg2ryMvYuXKAdNw23yCIywWMQzGNgeQerEfZ1jE
O1hZibCMjFCz2IbLaKPECudpSyDOwR5WS5WpI2jYMNjD67BVUc3l/Su49bsRn1NU
9jQZjHkJNsphFyUXC4KYcwx3dMPVDceoEkzHp1RxRy4sGn3J4ys7SN4nhKdjNrN9
j6BkOSQNPXuHr2ZcdBtLc7LljPCGmbjlxd+Ewbfr
-----END CERTIFICATE-----";

 inCert = FALSE;
 n = 0;

 if ( isnull(data) ) return NULL;
  foreach line (split(data, keep:FALSE)) {
      if ( line =~ "^-+BEGIN CERTIFICATE-+$" )
      {
        inCert = TRUE;
        der = NULL; 
      }
      else if (line =~ "^-+END CERTIFICATE-+$") 
      {
        raw[n] = base64_decode(str:der);
        ret[n] = parse_der_cert(cert:raw[n]);
        n++;
        der = NULL;
        inCert = FALSE;
      }
      else if ( inCert ) der += line;
    }

  r[0] = ret;
  r[1] = raw;
  return r;
}




function report_add_cert()
{
 certChain[max_index(certChain)] = _FCT_ANON_ARGS[0];
}


function report_add_problem(idx, msg)
{
 certProblemIdx = idx;
 certProblem = msg;
}


function reset_report()
{
 certChain = make_list();
 certProblemIdx = -2;
 certProblem = NULL;
}

function format_report()
{
 local_var ret;
 local_var i;
 local_var lines, line;

 ret = '';
 if ( certProblemIdx == -1 ) 
 {
  ret += '*** ERROR: ' + certProblem + '\nCertificate chain:\n';
  
 }


 for ( i = max_index(certChain) - 1; i >= 0 ; i -- )
 {
   if ( certProblemIdx == i ) 
   {
   lines = split(certProblem);
   ret += '|' + crap(length:max_index(certChain) - i - 1, data:'-') + '- *** ERROR:\n';
   foreach line ( lines )
   {
    ret += ereg_replace(pattern:'^', replace:'|' + crap(length:max_index(certChain) - i - 1, data:'-') + '- ***', string:line);
   }
   }
   lines = split(certChain[i]);
   foreach line ( lines )
   {
    if ( line =~ "^ *$" ) continue;
    ret += ereg_replace(pattern:'^', replace:'|' + crap(length:max_index(certChain) - i - 1, data:'-') + '-', string:line);
   }
   ret += '|\n';
 }
 return ret;
}





function validate_cert(cert, CA)
{
 local_var i, c, d, s, n, e, x;
 local_var parsed_certs;
 local_var unsigned_cert;
 local_var seq;
 local_var CA0, CA1;
 local_var tmp;
 local_var found;

 n = 0;
 CA0 = CA[0];
 CA1 = CA[1];
 parsed_certs = make_list();
 for ( i = 0 ; i < max_index(cert) ; i ++ )
 {
  parsed_certs[i] = parse_der_cert(cert:cert[i]);
  if ( !isnull(parsed_certs[i]) ) {
	seq = parsed_certs[i];
	seq = seq["tbsCertificate"];
  }
  else return -1; # ???
 }




 #
 # We don't verify the entire chain, we just want to verify if DigiNotar is somewhere in the way
 # 
 found = FALSE;
 for ( i = 0 ; i < max_index(cert) && found == FALSE; i ++ )
 {
 c = parse_der_cert(cert:cert[i]);
 tmp = c["tbsCertificate"];
 report_add_cert(add_rdn_seq_nl(seq:tmp["subject"]));
 
 d = find_issuer_idx(CA:CA0, cert:tmp);
 if ( d < 0 ) continue;
 d = CA0[d];
 tmp = d["tbsCertificate"];
 report_add_cert(add_rdn_seq_nl(seq:tmp["subject"]));
 found = TRUE;

 


 s = c["signatureValue"];
 tmp = d["tbsCertificate"];
 tmp = tmp["subjectPublicKeyInfo"];
 tmp = tmp[1];
 n = tmp[0];
 e = tmp[1];



 if ( ord(s[0]) == 0 ) s = substr(s, 1, strlen(s) - 1);
 if ( ord(n[0]) == 0 ) n = substr(n, 1, strlen(n) - 1);

 x = rsa_public_decrypt(sig:s, n:n, e:e);
 seq = der_parse_sequence (seq:cert[i],list:TRUE);

 unsigned_cert = seq[1];


 if ( c["signatureAlgorithm"] == "1.2.840.113549.1.1.11" )
 {
   if (!defined_func("SHA256"))
   {
	return -1;
   }
   if ( SHA256(unsigned_cert) >!< x ) 
   {
	return 1;
   }
 }
 else if ( c["signatureAlgorithm"] == "1.2.840.113549.1.1.5" )
 {
   if ( SHA1(unsigned_cert) >!< x ) return 1;
 }
 else if ( c["signatureAlgorithm"] ==  "1.2.840.113549.1.1.4" )
  {
   if ( MD5(unsigned_cert) >!< x ) return 1;
  }
  else if ( c["signatureAlgorithm"] ==  "1.2.840.113549.1.1.3" )
  {
   if ( MD4(unsigned_cert) >!< x ) return 1;
  }
 else if ( c["signatureAlgorithm"] ==  "1.2.840.113549.1.1.2" )
  {
    if ( MD2(unsigned_cert) >!< x ) return 1;
  }
  else return -1;
 }

 tmp = c["tbsCertificate"];

 if ( found ) 
 {
   report_add_problem(idx:-1, msg:'DigiNotar root CA in the chain:\n' + add_rdn_seq_nl(seq:tmp['issuer']) + '\n');
   return 0;
 }

 return 1;
}




#
# Load the CAs prior to forking
# 


allCA = load_DigiNotar();
if ( isnull(allCA) || isnull(allCA[0]) || max_index(allCA[0]) == 0 ) exit(1, "Could not load the list of SSL certificates.");

foreach port ( ports )
{
 reset_report();
 cert = get_server_cert(port:port, getchain:TRUE, encoding:"der");
 if ( isnull(cert) || max_index(cert) == 0 ) continue;
 e = validate_cert(cert:cert, CA:allCA);

 if ( e == 0 ) security_warning(port:port, extra:format_report());
  
}
