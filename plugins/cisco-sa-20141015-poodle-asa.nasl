#TRUSTED 824a88afa188defb6ed52ba3e258b17f17afa8b87502d9d6c9246beacb97a857c5bc11e124f8bf17119cd049c61b68479d87126bc93ae8177debf32c8295f7466194cb82793c1632b19ed07b4c5c45bd2e8270561e62d4999c4d2891565d05bcf883e5b2e73bd1695b3a96cf4b01bd20d79744a0708a264225c262a2c80ee16b0c4e6f7314332438d1dcfe4f42186ec74dd6bb90e08610f6ddc509bad863ae94e37e9663650485470fdc37bda167887e3350b8abc3039c45a2e654c9bfe5d53d8e6b89ce4d4d372d2e6c4f457ed1c9e5758569f5f9e1b0e256d441a35d981c0e39bde192c91607f4dd23e80bbfdcc52f002e0a8daad33b23bf724a6aeb5f9022b39b5a364edd3179ac87930eb5c59a7976858e5fea2e8c238f6d200ad924005f26376be1f6a234d5317fc3038605491dd2f3402d26949a4394d97e013443cc99b7fcbe50e63d4e42932db350d1c3675a3bf56419b577a4839fdc18197d713ffbe92da2d078f11843f0c17531f68a7ee7218519e43f2bcb68cc59500337347aba11e702b2f5f8d39fc7272a39d348ad22f1b23ae3ef90cb18360336bdfabb9824376ec1025a0ca288c532e84342a66095728535ffc27d95c0acdadd2e726949b68f52443047baac1d8e3e45eb490bdf1faf95a89c242e531abda31c82eddef0c47490708c91e7a29eb8eda371130a1fd9e1b8751592b2f34bc58b0fc6f588fcce
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78750);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/05/24");

  script_cve_id("CVE-2014-3566");
  script_bugtraq_id(70574);
  script_osvdb_id(113251);
  script_xref(name:"CERT", value:"577193");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur23709");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20141015-poodle");

  script_name(english:"SSLv3 Padding Oracle On Downgraded Legacy Encryption in Cisco ASA Software (cisco-sa-20141015-poodle) (POODLE)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a man-in-the-middle (MitM)
information disclosure vulnerability known as POODLE.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco ASA device is affected by a man-in-the-middle (MitM)
information disclosure vulnerability known as POODLE. The
vulnerability is due to the way SSL 3.0 handles padding bytes when
decrypting messages encrypted using block ciphers in cipher block
chaining (CBC) mode. A MitM attacker can decrypt a selected byte of a
cipher text in as few as 256 tries if they are able to force a victim
application to repeatedly send the same data over newly created SSL
3.0 connections.

Note that all versions of ASA are affected; however, the workaround
does not work for versions 8.0.x, 8.1.x, 9.0.x, and 9.1(1)x. Please
refer to the advisory or contact the vendor for possible solutions.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20141015-poodle
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7453d3be");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCur23709");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Apply the workaround by disabling SSLv3 referenced in the Cisco bug ID
CSCur23709, or contact the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

flag = 0;
override = 0;
fixed_ver = "";
report = "";


# #################################################
# CSCur23709
# #################################################
cbi = "CSCur23709";
flag = 0;
sp_flag = 0;

# Vulnerable version information pulled from cisco-sa-20141008-asa
if (ver =~ "^7[^0-9]")
  flag++;

else if (ver =~ "^8\.0[^0-9]")
  sp_flag++;

else if (ver =~ "^8\.1[^0-9]")
  sp_flag++;

else if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.55)"))
  flag++;

else if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.43)"))
  flag++;

else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.26)"))
  flag++;

else if (ver =~ "^8\.5[^0-9]" && check_asa_release(version:ver, patched:"8.5(1.23)"))
  flag++;

else if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.16)"))
  flag++;

else if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.15)"))
  flag++;

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.26)"))
  sp_flag++;

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(5.21)"))
  flag++;

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(3)"))
  flag++;

else if (ver =~ "^9\.3\([01][^0-9]" && check_asa_release(version:ver, patched:"9.3(1.1)"))
  flag++;

else if (ver =~ "^9\.3\(2[^0-9]" && check_asa_release(version:ver, patched:"9.3(2.2)"))
  flag++;

if (flag)
{
  flag = 0;
  # Check for the workaround
  buf = cisco_command_kb_item("Host/Cisco/Config/show_run_all_ssl", "show run all ssl");
  if (check_cisco_result(buf))
  {
    # Both the server and the client need to be configured.
    if (!preg(multiline:TRUE, pattern:"ssl server-version tlsv1", string:buf)) flag++;
    if (!preg(multiline:TRUE, pattern:"ssl client-version tlsv1-only", string:buf)) flag++;
  }
  else if (cisco_needs_enable(buf)) {flag = 1; override = 1;}
}

if (flag || sp_flag)
{
  if (report_verbosity > 0)
  {
    report +=
      '\n  Cisco bug ID      : ' + cbi +
      '\n  Installed release : ' + ver +
      '\n';
    security_warning(port:0, extra:report+cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
