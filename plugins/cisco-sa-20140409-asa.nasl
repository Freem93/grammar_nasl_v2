#TRUSTED 2b9349fedc36485ee06c51282fa087567da508fe8291eff1b18b586afcde8b22d0b3d66f029b24b0bbcfc03fb7179de4ed44350011d8272660f2d71ffe2d8af3070ef0897ea6a79b65f4528406fbd2ac589b8eec04d7c49d510c84319af1e5162cbeef5141b1f566a4a4b470c0fa9cffe86e8b00f778e7381b9680f2643f234623e04db150d02570d9f05edab3e187db2a8add5a84b6aad0c31fbf1b6284295d1ca4806c25f2cc2565db1e6f058b5d06598d8f3b61722ace6a2c9e1216d03cee7e975e8490d289d6f948073f4dc85652bfc16e94fe642e2365d5ae76e50b3c398f35a4b36d5195636ccaef6cbf4c88422880802ca2718ab7212d557faf24f7c7eb7630f7448bb7bb2773ed28a217d4b6a2231e8826442a208317e20c867769f71024adc2eac94a1239794a0aa09072eb1a1cb2edb0e03b204bda33d34a065e64b075a3fd924a28c8429ea2a09e981ecb2144f82ceb25c1e702c7eada25cfc9fc8f1dfd11de8484df012fd7511a01fbdbee069d3285a94a2b756a74ebc87cc5a6cade42e61ce106eb053651c2153f3776b660ac41072a24b89b94271c619841cc398970dd082aaa9391edf9a81701c1a702c2accf26297fb14ab1a745a31b7c4ced39503c8041b2212ca91ad8ad5198e830b5dfef60033e09cf45da5bcc1fcba634c4d741615570ea7efa89a19bf7c210b1603144201360dab60bed94cad01227
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73533);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/05/14");

  script_cve_id(
    "CVE-2014-2126",
    "CVE-2014-2127",
    "CVE-2014-2128",
    "CVE-2014-2129"
  );
  script_bugtraq_id(66745, 66746, 66747, 66748);
  script_osvdb_id(105607, 105608, 105609, 105610);
  script_xref(name:"CISCO-BUG-ID", value:"CSCua85555");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh44052");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj33496");
  script_xref(name:"CISCO-BUG-ID", value:"CSCul70099");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140409-asa");

  script_name(english:"Cisco ASA Software Multiple Vulnerabilities (cisco-sa-20140409-asa)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco ASA device is affected by one or more of the
following vulnerabilities :

  - An issue exists in the Adaptive Security Device Manager
    (ADSM) due to improper privilege assignment to users
    with a privilege level of zero. This issue allows an
    authenticated, remote attacker to gain administrative
    privileges. (CVE-2014-2126)

  - An issue exists in the SSL VPN portal when the
    Clientless SSL VPN feature is used due to improper
    handling of management session information. An
    authenticated, remote attacker can exploit this to gain
    administrative privileges. (CVE-2014-2127)

  - An issue exists in the SSL VPN feature due to improper
    handling of authentication cookies. An unauthenticated,
    remote attacker can exploit this to bypass
    authentication, resulting in unauthorized access to
    internal network resources. (CVE-2014-2128)

  - An issue exists in the SIP inspection engine due to
    improper handling of SIP packets. An unauthenticated,
    remote attacker can exploit this to cause memory
    exhaustion, resulting in a denial of service.
    (CVE-2014-2129)

Note that that the verification check for the presence of
CVE-2014-2128 is a best effort approach and may result in potential
false positives.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140409-asa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6fcb7e97");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch or workaround referenced in Cisco Security
Advisory cisco-sa-20140409-asa.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_5500");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_6500");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_7600");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_1000V");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/15");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

# Verify that we are targeting an affected hardware model
#   Cisco ASA 5500 Series Adaptive Security Appliances
#   Cisco ASA 5500-X Next Generation Firewall
#   Cisco ASA Services Module for Cisco Catalyst 6500 Series Switches
#   Cisco 7600 Series Routers
#   Cisco ASA 1000V Cloud Firewall
if (
  model !~ '^55[0-9][0-9]($|[^0-9])' &&
  model !~ '^65[0-9][0-9]($|[^0-9])' &&
  model !~ '^76[0-9][0-9]($|[^0-9])' &&
  model !~ '^1000V'
) audit(AUDIT_HOST_NOT, "ASA 5500 5000-X 6500 7600 or 1000V");

flag = 0;
report_extras = "";
fixed_ver = "";
local_check = 0;
override = 0;

# For each vulnerability, check for affected OS versions,
# set "fixed" os version, and perform any additional checks

# Determine if additional local checks can be performed
if (
  get_kb_item("Host/local_checks_enabled")
) local_check = 1;

# #################################################
# CSCuj33496
# #################################################
cbi = "CSCuj33496";
temp_flag = 0;

if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.47)"))
{
  temp_flag++;
  fixed_ver = "8.2(5)47";
}

else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.5)"))
{
  temp_flag++;
  fixed_ver = "8.4(7)5";
}

else if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.11)"))
{
  temp_flag++;
  fixed_ver = "8.7(1)11";
}

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(3.10)"))
{
  temp_flag++;
  fixed_ver = "9.0(3)10";
}

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(3.4)"))
{
  temp_flag++;
  fixed_ver = "9.1(3)4";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    # Check if HTTP is enabled
    buf = cisco_command_kb_item(
      "Host/Cisco/Config/show_running-config_http",
      "show running-config http"
    );
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"http server enable", string:buf))
      {
        # Check if a user has been assigned privilege level 0
        buf = cisco_command_kb_item(
          "Host/Cisco/Config/show_running-config_username_include_privilege_0",
          "show running-config username | include privilege 0"
        );
        if (check_cisco_result(buf))
        {
          if (preg(multiline:TRUE, pattern:"privilege 0$", string:buf))
            temp_flag = 1;
        }
        else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
      }
    }
    else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}
# #################################################
# CSCul70099
# #################################################
cbi = "CSCul70099";
temp_flag = 0;

if (ver =~ "^8\.[01][^0-9]")
{
  temp_flag++;
  fixed_ver = "This branch is no longer supported. Refer to the vendor for a fix.";
}

else if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.48)"))
{
  temp_flag++;
  fixed_ver = "8.2(5)48";
}

else if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.40)"))
{
  temp_flag++;
  fixed_ver = "8.3(2)40";
}

else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.9)"))
{
  temp_flag++;
  fixed_ver = "8.4(7)9";
}

else if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.13)"))
{
  temp_flag++;
  fixed_ver = "8.6(1)13";
}

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.1)"))
{
  temp_flag++;
  fixed_ver = "9.0(4)1";
}

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(4.3)"))
{
  temp_flag++;
  fixed_ver = "9.1(4)3";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    # Check if SSL VPN (WebVPN) feature is enabled
    buf = cisco_command_kb_item(
      "Host/Cisco/Config/show_running-config_webvpn",
      "show running-config webvpn"
    );
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"enable", string:buf))
        temp_flag = 1;
    }
    else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n    Cisco bug ID      : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCua85555
# #################################################
cbi = "CSCua85555";
temp_flag = 0;

if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.47)"))
{
  temp_flag++;
  fixed_ver = "8.2(5)47";
}

else if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.40)"))
{
  temp_flag++;
  fixed_ver = "8.3(2)40";
}

else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.3)"))
{
  temp_flag++;
  fixed_ver = "8.4(7)3";
}

else if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.13)"))
{
  temp_flag++;
  fixed_ver = "8.6(1)13";
}

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(3.8)"))
{
  temp_flag++;
  fixed_ver = "9.0(3)8";
}

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(3.2)"))
{
  temp_flag++;
  fixed_ver = "9.1(3)2";
}


if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    # Check if SSL VPN (WebVPN) feature is enabled
    buf = cisco_command_kb_item(
      "Host/Cisco/Config/show_running-config_webvpn",
      "show running-config webvpn"
    );
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"enable", string:buf))
      {
        # Versions 8.2.x and 8.3.x are not affected if HostScan feature is enabled AND
        # certificate-only authentication is used for SSL VPN authentication
        if (ver =~ "^8\.[23][^0-9]")
        {

          buf = cisco_command_kb_item(
            "Host/Cisco/Config/show-webvpn-csd-hostscan",
            "show webvpn csd hostscan"
          );
          if (check_cisco_result(buf))
          {
            if (!preg(multiline:TRUE, pattern:"and enabled", string:buf))
            {

              buf = cisco_command_kb_item(
                "Host/Cisco/Config/show_running-config_all_tunnel-group",
                "show running-config all tunnel-group"
              );
              if (check_cisco_result(buf))
              {
                if (preg(multiline:TRUE, pattern:"authentication (aaa )?certificate", string:buf))
                  temp_flag = 1;
              }
              else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
            }
          }
          else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
        }

        # Check if 'authorization-required' is enabled in *ANY* tunnel group
        buf = cisco_command_kb_item(
          "Host/Cisco/Config/show_running-config_all_tunnel-group",
          "show running-config all tunnel-group"
        );
        if (check_cisco_result(buf))
        {
          if (!preg(multiline:TRUE, pattern:"^\s*authorization-required", string:buf))
            temp_flag = 1;
        }
        else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
      }
    }
    else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n    Cisco bug ID      : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCuh44052
# #################################################
cbi = "CSCuh44052";
temp_flag = 0;

if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.48)"))
{
  temp_flag++;
  fixed_ver = "8.2(5)48";
}

if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(6.5)"))
{
  temp_flag++;
  fixed_ver = "8.4(6.5)";
}

if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(3.1)"))
{
  temp_flag++;
  fixed_ver = "9.0(3)1";
}

if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(2.5)"))
{
  temp_flag++;
  fixed_ver = "9.1(2)5";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item(
      "Host/Cisco/Config/show_service-policy-include-sip",
      "show service-policy | include sip"
    );
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, icase:TRUE, pattern:"Inspect: sip", string:buf))
        temp_flag = 1;
    }
    else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n    Cisco bug ID      : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}


if (flag)
{
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
