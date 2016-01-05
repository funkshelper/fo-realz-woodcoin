# fo-realz-woodcoin

{}...A funkenstein_the_dwarf production...{}

Woodcoin a la "therealbitcoin".
This is a fork of the reference node project found here: (therealbitcoin.org , thebitcoin.foundation).

This is a retro version of Woodcoin.  Command line only.  
It syncs far slower than more common wallet versions.

This thing also builds statically with buildroot/musl toolchain as described 
in therealbitcoin and related documentation.

This is a hardened war-ready full node and wallet for woodcoin, 
for post-apocalypse and heavy battlefield use.
Also can be used as reference implementation due to minimal external libraries. 

Github is not guaranteed to be entirely reliable in such scenarios 
as those when this version becomes crucial to the network.
  
Therefore it is suggested to keep a copy of this thing in local rad-hard storage, 
and to use the tarballed src directory (verify the signature).

This release includes the following "therealbitcoin" patches:

asciilifeform_add_verifyall_option.vpatch <br/>
asciilifeform_and_now_we_have_block_dumper_corrected.vpatch <br/>
asciilifeform_and_now_we_have_eatblock.vpatch <br/>
asciilifeform_dnsseed_snipsnip.vpatch <br/>
asciilifeform_dns_thermonyukyoolar_kleansing.vpatch <br/>
asciilifeform-kills-integer-retardation.vpatch <br/>
asciilifeform_lets_lose_testnet.vpatch <br/>
asciilifeform_maxint_locks_corrected.vpatch <br/>
asciilifeform_orphanage_thermonuke.vpatch <br/>
asciilifeform_tx-orphanage_amputation.vpatch <br/>
asciilifeform_ver_now_5_4_and_irc_is_gone_and_now_must_give_ip.vpatch <br/>
asciilifeform_zap_hardcoded_seeds.vpatch <br/>
asciilifeform_zap_showmyip_crud.vpatch <br/>
bitcoin-asciilifeform.1.vpatch <br/>
bitcoin-asciilifeform.2-https_snipsnip.vpatch <br/>
bitcoin-asciilifeform.3-turdmeister-alert-snip.vpatch <br/>
bitcoin-asciilifeform.4-goodbye-win32.vpatch <br/>
bitcoin-v0_5_3_1-rev_bump.7.vpatch <br/>
bitcoin-v0_5_3_1-static_makefile_v002.8.vpatch <br/>
bitcoin-v0_5_3-db_config.6.vpatch <br/>
genesis.vpatch <br/>
mod6_fix_dumpblock_params.vpatch <br/>
rm_rf_upnp.vpatch <br/>
funk_add_privkey_wallet_tools.vpatch <br/>
funk_chuck_checkpoints.vpatch <br/>

Instructions:  

Download the code and verify either using <code>V</code> to press (late 2015 vintage V.pl is here with mod6' sig) or verifying the tar using the gpg key:

     pub   4096R/88298AB6 Funkenstein the Dwarf 

Build the daemon with:

     make -f makefile.unix

Run the first time with:  

     ./woodcoind -connect=<some node>  -myip=<myip> &

(If you have not done so, you will be prompted to manually build the bitcoin.conf file with rpcuser and password)

Depending on the locale setup in your build environment you might need to first issue: 

     export LC_ALL=C

After the client has connected the first time it will keep a list of nodes, in the future one only needs

     ./woodcoind &










