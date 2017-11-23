Repository for Bootstrap Scripts for Raspbian

<pre>prepare-image.sh</pre> downloads raspbian image, creates ssh keys, stores them and should (future) setup the vpn connection. Also furtur it shall load the ssh keys to the gitlab server for pulling latest updates from a future repository to get new scripts. ``

Change the options for your needs: 
<pre>
cp ./config/raspi-options.sh{_example,} 
vim ./config/raspi-options.sh 
</pre>
