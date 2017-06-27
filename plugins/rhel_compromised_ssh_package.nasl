#TRUSTED 6821beaa81989621720ca2ab2787c24cee44430379381484248b0ccd517a47fb50c0b33bc345c9ca800bb62853ec0833a7f8c083471135858fcd4687cc9d052c94b31413b29da705047030fd145aa6bc0acf058e06c1475503f7aa2c24b86a00f764e8c25dd8389a95ce582574f1cd529de00e5e3924f282e408751d082b4ca2ef5f96db4cdcf5f1a9276d5906e9124492e54811ad0ff9f110f2eb12f93af6a45884602bd614b5390ef53f780f7103fe2d805ae3288e9a2e53cca44345d657d3cd857780f6f016a4d439d428d128278f8017e364fd5e0bdf8f9fb114caa9a96bebb6519f6e390fa3a6caa7cfb613d416732aa10c7f8821c17008cd6b0abe722e77aa4128fe21b39aa31c4d92c81266486163e176d95ddb63dae0817b97ea5d3dccbbd3a9f90968a24d5b7d4b724f3c3f3637ead21a9a842dbf145103b05e22c16d531f4d63afad9d22e13b8a5d908d225d46ebc7c29221e58198ca48897e0e0156c7d166dacec3604692aa21cedcf6ff46b6d2bf891c252492940c5e4ef36386c01d311d2c16da83f40d5974531eae683dd1bb88f8922d0e1eaf8c6b621588d1d0b24d6b3cd58b3fe5b39c6a41d6977763b5c02b3f904db5c22360ec932aa1d55f2742c47b4ede3b676e2849c1bb2ecfec67d8f8b3088f216cee61752a822527138e436b9ac38d369fcd1230f2a52829f21a32d46237b9f3fb8d5e8c338252cc
#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);

include("compat.inc");

if(description)
{
 script_id(34030);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value: "2016/11/17");

 script_cve_id("CVE-2008-3844");
 script_bugtraq_id(30794);
 script_osvdb_id(47635);
 script_xref(name:"IAVT", value:"2008-T-0046");

 name["english"] = "Remote host has a compromised Red Hat OpenSSH package intalled";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has a compromised version of an OpenSSH-related
package installed." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a compromised version of an OpenSSH-related
package installed. 

Even though this package has been signed with the Red Hat public key,
this package is considered malicious, and the remote host should be
reinstalled." );
 script_set_attribute(attribute:"see_also", value:"http://www.redhat.com/security/data/openssh-blacklist.html" );
 script_set_attribute(attribute:"solution", value:
"Reintall the remote host." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
	
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/22");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"agent", value:"unix");
 script_set_attribute(attribute:"stig_severity", value:"II");
 script_end_attributes();
 
 script_summary(english:"Checks for the remote SSH packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"Red Hat Local Security Checks");

 script_dependencie("ssh_detect.nasl", "ssh_get_info.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");


list = make_list(
"Host/VMware/rpm-list",
"Host/RedHat/rpm-list",
"Host/CentOS/rpm-list",
"Host/Mandrake/rpm-list",
"Host/SuSE/rpm-list");

flag = 0;

foreach item ( list ) 
{
 if ( get_kb_item(item) ) flag ++;
} 

if ( ! flag ) exit(0);



if ( islocalhost() )
{
 info_t = INFO_LOCAL;
}
else
{
 sock_g = ssh_open_connection();
 if ( !sock_g ) exit(0);
 info_t = INFO_SSH;
}

md5 = make_list(
"00b6c24146eb6222ec58342841ee31b1",
"021d1401b2882d864037da406e7b3bd1",
"035253874639a1ebf3291189f027a561",
"08daefebf2a511852c88ed788717a148",
"177b1013dc0692c16e69c5c779b74fcf",
"24c67508c480e25b2d8b02c75818efad",
"27ed27c7eac779f43e7d69378a20034f",
"2a2f907c8d6961cc8bfbc146970c37e2",
"2b0a85e1211ba739904654a7c64a4c90",
"2df270976cbbbbb05dbdf95473914241",
"2ff426e48190519b1710ed23a379bbee",
"322cddd04ee5b7b8833615d3fbbcf553",
"35b050b131dab0853f11111b5afca8b3",
"38f67a6ce63853ad337614dbd760b0db",
"3b9e24c54dddfd1f54e33c6cdc90f45c",
"3fa1a1b446feb337fd7f4a7938a6385f",
"41741fe3c73d919c3758bf78efc437c9",
"432b94026da05d6b11604a00856a17b2",
"54bd06ebf5125debe0932b2f1f5f1c39",
"57f7e73ee28ba0cbbaad1a0a63388e4c",
"59ad9703362991d8eff9d138351b37ac",
"71ef43e0d9bfdfada39b4cb778b69959",
"760040ec4db1d16e878016489703ec6d",
"89892d38e3ccf667e7de545ea04fa05b",
"8a65c4e7b8cd7e11b9f05264ed4c377b",
"8bf3baa4ffec125206c3ff308027a0c4",
"982cd133ba95f2db580c67b3ff27cfde",
"990d27b6140d960ad1efd1edd5ec6898",
"9bef2d9c4c581996129bd9d4b82faafa",
"9c90432084937eac6da3d5266d284207",
"a1dea643f8b0bda52e3b6cad3f7c5eb6",
"b54197ff333a2c21d0ca3a5713300071",
"b92ccd4cbd68b3d3cefccee3ed9b612c",
"bb1905f7994937825cb9693ec175d4d5",
"bc6b8b246be3f3f0a25dd8333ad3456b",
"c0aff0b45ee7103de53348fcbedaf72e",
"c7d520faab2673b66a13e58e0346021d",
"ce97e8c02c146c8b1075aad1550b1554",
"d19ae2199662e90ec897c8f753816ee0",
"de61e6e1afd2ca32679ff78a2c3a0767",
"dfbc24a871599af214cd7ef72e3ef867",
"f68d010c6e54f3f8a973583339588262",
"fc814c0e28b674da8afcfbdeecd1e18e"
);

res = info_send_cmd(cmd:'rpm -q --qf "%{NAME}/%{SIGMD5}\\n" openssh openssh-askpass openssh-askpass-gnome openssh-clients openssh-debuginfo openssh-server');

if ( ! res ) exit(0);
report = NULL;
foreach md (md5) 
{
 if ( md >< res )
 {
   line = chomp(egrep(pattern:md, string:res));
   split = split(line, sep:'/',keep:0);
   report += 'Package name : ' + split[0]  + '\nPackage MD5 : ' + split[1] + '\n\n';
 }
}

if ( report )
{
 security_hole(port:0, extra:'\nThe following packages are vulnerables :\n' + report);
}
