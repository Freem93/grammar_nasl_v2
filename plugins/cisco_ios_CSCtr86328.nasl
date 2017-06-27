#TRUSTED 58a1a0c3632ce336b4254d0718ca838f17f8a8f3f81b5ff7ad57a68e30475e399f52ef59b0687f274fed9a963a381017c292768542816cff96c5ad189c09606d7b654fac85d42465b1f39fa1f8f7a0e40bac96515e364bad16a5cfd99cdabaf1e256ffed1ae3158d49a77fb1773569404f88fa8469476c85e8a7d147864fb0512551971d878ad4b62043faafe3abd72b2af6375dccfc198e74b2419998dadc3a5d7d33c8e7b900ed82008915f434785a0e5164b8a728d65b0f640865135e3b613fbf0455b9f24b9c2fbdfd7f9d6ed7f3526d4f385e8e596150d2df9df09b0bc1eef67c7f72944ab1575738b7af69bb7981b1bda80d67287bda2b4ec344f582307ee1e04d6e7cc13709dfc71c3f54dfe0b8bd0be2bd62b14ec8fec46d15838927d1ddda11c605688f68ed25e05b0cfe0daa9c2bff3c9795b50d5cb1eab605a997a96fcfe5a101d19249d26f4af827ee9c5a367299728ee0ce1860c5ab14e7f6fae0db4816030ae8944dce8449ae9f15de3ed47a95e47c6517aff7c828811c578878caacf6ec9d56e235e872dcb62ce1ac574214b1b66dd69cad58c290d71267aa24b7fbbd15f1671a9fe1961f713a02a252b4d86f7cf09d637fa46a399baebf7905a694c1324c7c976c0d211aa47b4e28363b2e16fe52fc9994f89d1fa9bd4578e76280aa82f64e6b1de2bd697614b9ca6bf17edda9fbdb39f7907bc0485855e7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description){
  script_id(61576);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/27");

  script_cve_id("CVE-2012-1344");
  script_bugtraq_id(54835);
  script_osvdb_id(84503);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtr86328");

  script_name(english:"Cisco IOS Clientless SSL VPN DoS");
  script_summary(english:"Checks IOS version");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS device is configured for clientless SSL VPN. It
is, therefore, affected by a denial of service vulnerability due to an 
unspecified flaw that causes a device reload when using a web browser
to refresh the SSL VPN portal page. A remote, authenticated attacker
can exploit this to cause a denial of service.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=26602");
  script_set_attribute(attribute:"solution", value:
"Contact Cisco for updated software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

flag = 0;

if (ver =='15.1(2)T') flag++;
if (ver =='15.1(2)EY') flag++;
if (ver =='15.1(2)EY1') flag++;
if (ver =='15.1(2)EY1a') flag++;
if (ver =='15.1(2)EY2') flag++;
if (ver =='15.1(2)EY2a') flag++;
if (ver =='15.1(2)EY3') flag++;
if (ver =='15.1(2)EY4') flag++;
if (ver =='15.1(2)GC') flag++;
if (ver =='15.1(2)GC1') flag++;
if (ver =='15.1(2)GC2') flag++;
if (ver =='15.1(4)M') flag++;
if (ver =='15.1(4)M0a') flag++;
if (ver =='15.1(4)M0b') flag++;
if (ver =='15.1(4)M1') flag++;
if (ver =='15.1(4)M2') flag++;
if (ver =='15.1(4)M3') flag++;
if (ver =='15.1(4)M3a') flag++;
if (ver =='15.1(1)MR') flag++;
if (ver =='15.1(1)MR1') flag++;
if (ver =='15.1(1)MR2') flag++;
if (ver =='15.1(1)MR3') flag++;
if (ver =='15.1(1)MR4') flag++;
if (ver =='15.1(3)MR') flag++;
if (ver =='15.1(3)MR1') flag++;
if (ver =='15.1(2)MWR') flag++;
if (ver =='15.1(1)S') flag++;
if (ver =='15.1(1)S1') flag++;
if (ver =='15.1(1)S2') flag++;
if (ver =='15.1(2)S') flag++;
if (ver =='15.1(2)S1') flag++;
if (ver =='15.1(2)S2') flag++;
if (ver =='15.1(3)S') flag++;
if (ver =='15.1(3)S0a') flag++;
if (ver =='15.1(3)S1') flag++;
if (ver =='15.1(3)S2') flag++;
if (ver =='15.1(3)S3') flag++;
if (ver =='15.1(3)S4') flag++;
if (ver =='15.1(1)SA') flag++;
if (ver =='15.1(1)SA1') flag++;
if (ver =='15.1(1)SA2') flag++;
if (ver =='15.1(1)SG') flag++;
if (ver =='15.1(1)SG1') flag++;
if (ver =='15.1(2)SG') flag++;
if (ver =='15.1(2)SNH') flag++;
if (ver =='15.1(2)SNH1') flag++;
if (ver =='15.1(2)SNI') flag++;
if (ver =='15.1(3)SVA') flag++;
if (ver =='15.1(1)SY') flag++;
if (ver =='15.1(1)SY1') flag++;
if (ver =='15.1(1)T') flag++;
if (ver =='15.1(1)T1') flag++;
if (ver =='15.1(1)T2') flag++;
if (ver =='15.1(1)T3') flag++;
if (ver =='15.1(1)T4') flag++;
if (ver =='15.1(1)T5') flag++;
if (ver =='15.1(100)T') flag++;
if (ver =='15.1(2)T0a') flag++;
if (ver =='15.1(2)T1') flag++;
if (ver =='15.1(2)T10') flag++;
if (ver =='15.1(2)T2') flag++;
if (ver =='15.1(2)T2a') flag++;
if (ver =='15.1(2)T3') flag++;
if (ver =='15.1(2)T4') flag++;
if (ver =='15.1(2)T5') flag++;
if (ver =='15.1(3)T') flag++;
if (ver =='15.1(3)T1') flag++;
if (ver =='15.1(3)T2') flag++;
if (ver =='15.1(3)T3') flag++;
if (ver =='15.1(3)T4') flag++;
if (ver =='15.1(4)T') flag++;
if (ver =='15.1(1)XB') flag++;
if (ver =='15.1(1)XB1') flag++;
if (ver =='15.1(1)XB2') flag++;
if (ver =='15.1(1)XB3') flag++;
if (ver =='15.1(4)XB4') flag++;
if (ver =='15.1(4)XB5') flag++;
if (ver =='15.1(4)XB5a') flag++;
if (ver =='15.1(4)XB6') flag++;
if (ver =='15.1(4)XB7') flag++;
if (ver =='15.1(4)XB8') flag++;
if (ver =='15.1(4)XB8a') flag++;
if (ver =='15.2(1)E') flag++;
if (ver =='15.2(1)GC') flag++;
if (ver =='15.2(1)GC1') flag++;
if (ver =='15.2(1)GC2') flag++;
if (ver =='15.2(2)GC') flag++;
if (ver =='15.2(3)GC') flag++;
if (ver =='15.2(2)JA') flag++;
if (ver =='15.2(4)M') flag++;
if (ver =='15.2(4)M0a') flag++;
if (ver =='15.2(4)M1') flag++;
if (ver =='15.2(4)M10') flag++;
if (ver =='15.2(4)M2') flag++;
if (ver =='15.2(4)M3') flag++;
if (ver =='15.2(4)M4') flag++;
if (ver =='15.2(4)M5') flag++;
if (ver =='15.2(4)M6') flag++;
if (ver =='15.2(4)M7') flag++;
if (ver =='15.2(4)M8') flag++;
if (ver =='15.2(4)M9') flag++;
if (ver =='15.2(1)S') flag++;
if (ver =='15.2(1)S1') flag++;
if (ver =='15.2(1)S2') flag++;
if (ver =='15.2(1s)S1') flag++;
if (ver =='15.2(2)S') flag++;
if (ver =='15.2(2)S0a') flag++;
if (ver =='15.2(2)S0b') flag++;
if (ver =='15.2(2)S0c') flag++;
if (ver =='15.2(2)S0d') flag++;
if (ver =='15.2(2)S1') flag++;
if (ver =='15.2(2)S2') flag++;
if (ver =='15.2(3)S') flag++;
if (ver =='15.2(4)S') flag++;
if (ver =='15.2(4)S1') flag++;
if (ver =='15.2(4)S2') flag++;
if (ver =='15.2(4)S3') flag++;
if (ver =='15.2(4)S4') flag++;
if (ver =='15.2(4)S5') flag++;
if (ver =='15.2(4)S6') flag++;
if (ver =='15.2(1)SB') flag++;
if (ver =='15.2(1)SB1') flag++;
if (ver =='15.2(2)SNG') flag++;
if (ver =='15.2(1)T') flag++;
if (ver =='15.2(1)T1') flag++;
if (ver =='15.2(1)T2') flag++;
if (ver =='15.2(1)T3') flag++;
if (ver =='15.2(1)T4') flag++;
if (ver =='15.2(2)T') flag++;
if (ver =='15.2(2)T1') flag++;
if (ver =='15.2(2)T2') flag++;
if (ver =='15.2(2)T3') flag++;
if (ver =='15.2(2)T4') flag++;
if (ver =='15.2(3)T') flag++;
if (ver =='15.2(3)T1') flag++;
if (ver =='15.2(3)T2') flag++;
if (ver =='15.2(3)T3') flag++;
if (ver =='15.2(3)T4') flag++;
if (ver =='15.2(3)XA') flag++;

if (get_kb_item("Host/local_checks_enabled") && flag)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if ("webvpn" >< buf) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug IDs     : CSCtr86328' +
      '\n  Installed release : ' + ver +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
