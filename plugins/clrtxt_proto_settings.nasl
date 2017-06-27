#TRUSTED 7af369dc7c2961a5c4317264e7c3400e1cf9129310d22b802604a9cf6d0ce919e89352dc520bee8ae7c95dd78ad075e15eb5892db2d11d92af8ba86afb584bdb89ee151064894203120cd4a6112e6240bc34e62123c28eb393b9b10eb8e844a635cf026710d53a77e4355da927d3f7b396f636564679012d77ce5a90bf644bbf5c1a27455d7173b7435d1f050d464766d4025d4b0fe2027788728f68f862745b456d1492967bf39354fa869ef49db3e966fcbe010b2f9f2a4b0af85a26d09211b4370a440a24eed28a87925a3864e57e59d653722e43f5a721f2515d382bb9c67ed45b85697ac84e1e2752374b878389e22604e1968bd68b53d151b391ef51173cb6457691405f7db5dd8d598722465357f82b76a5f905843e4be719ffae70e43b38cd465ecc0e7dcc3d5c988d0006be0e7eef29eb5c7aabd30f7888d4c9ef8f2ded59fb6dfccb215ec94dcc77de4f8ea213c4b52be7711aa2a53c171e359968cd8b527adc601940abbe62295a87cfbc22ffd9cfad0fbcffb2650d4ffd86438d4e6de76611786610e42a672bc2cc79830c74b9d6dc41481e04675fc0fc99e3293a81bc0a9f23a51939d20fa775c638ce64c60563b75053bae72a0aaf5bafd7be31dca2138aa4d7877445b3764d3c1731e525304cca93f1c9c93dcded5bbdd5ef1f7a6b5bc19d88247175d0a495ecea0219cfebba4e585619c79fe8cfca6e30dc
#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(21744);
 script_version("1.7");
 script_set_attribute(attribute:"plugin_modification_date", value: "2010/12/30");

 script_name(english:"Cleartext protocols settings");
 script_summary(english:"Set cleartext credentials to perform local security checks");

 script_set_attribute(
   attribute:"synopsis",
   value:"This script is used to configure Nessus settings."
 );
 script_set_attribute( attribute:"description", value:
"This script just sets global variables (telnet/rexec/rsh logins and
passwords) that are used to perform host-level patch level checks.

You should avoid using these cleartext protocols when doing a scan,
as Nessus will basically broadcast the password to every tested host." );
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/06/23");
 script_set_attribute(attribute:"plugin_type", value:"settings");
 script_end_attributes();

 script_category(ACT_INIT);
 script_family(english:"Settings");

 script_copyright(english:"Copyright (C) 2006-2011 Tenable Network Security, Inc.");

 script_add_preference(name:"User name : ", type:"entry", value:"");
 script_add_preference(name:"Password (unsafe!) : ", type:"password", value:"");
 script_add_preference(name:"Try to perform patch level checks over telnet", type:"checkbox", value:"no");
 #script_add_preference(name:"Try to perform patch level checks over rlogin", type:"checkbox", value:"no");
 script_add_preference(name:"Try to perform patch level checks over rsh", type:"checkbox", value:"no");
 script_add_preference(name:"Try to perform patch level checks over rexec", type:"checkbox", value:"no");

 exit(0);
}

account    = script_get_preference("User name : ");
password   = script_get_preference("Password (unsafe!) : ");

try_telnet = script_get_preference("Try to perform patch level checks over telnet");
#try_rlogin = script_get_preference("Try to perform patch level checks over rlogin");
try_rsh    = script_get_preference("Try to perform patch level checks over rsh");
try_rexec  = script_get_preference("Try to perform patch level checks over rexec");

if ( account  ) set_kb_item(name:"Secret/ClearTextAuth/login", value:account);
if ( password ) set_kb_item(name:"Secret/ClearTextAuth/pass", value:password);

if ( try_telnet == "yes" ) set_kb_item(name:"HostLevelChecks/try_telnet", value:TRUE);
#if ( try_rlogin == "yes" ) set_kb_item(name:"HostLevelChecks/try_rlogin", value:TRUE);
if ( try_rsh    == "yes" ) set_kb_item(name:"HostLevelChecks/try_rsh",    value:TRUE);
if ( try_rexec  == "yes" ) set_kb_item(name:"HostLevelChecks/try_rexec",    value:TRUE);
