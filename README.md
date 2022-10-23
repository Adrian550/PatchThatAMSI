# PatchThatAMSI  
## Tested on windows 10, patch 1,2 not working on windows11 others work
this repo contains 6 AMSI patches , all force the triggering of a conditional jump inside AmsiOpenSession()  that close the Amsi scanning session.   
The 1st patch by corrupting the Amsi context header.  
The 2nd patch by changing the string "AMSI" that will be compared to the Amsi context header to "D1RK".  
The Others set ZF to 1 and trigger the jump.

## Images
![AMSI1](https://user-images.githubusercontent.com/110354855/197331910-829816a0-a7a0-4cda-b72e-ab05f2692a64.png)

![AMSI2](https://user-images.githubusercontent.com/110354855/197331928-8bc98ecb-0b03-498e-a756-83288db40a90.png)
