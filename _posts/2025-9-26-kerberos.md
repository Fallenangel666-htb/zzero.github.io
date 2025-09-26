---
layout: single
title: explicacion de kerberos
excerpt:
date: 2025-9-26
classes: wide
header:
  teaser: https://upload.wikimedia.org/wikipedia/en/1/1e/Kerberos_protocol_logo.png
  teaser_home_page: true
categories:
  - hacking
  - Windows
  - Teoria
  - kerberos
  - C2
tags:
  - hacking
  - Windows
  - Teoria
  - kerberos
  - C2
---


SOY UNA CREMA DE CACAHUETe

Como soy sadomaso voy a intentar explicar kerberos, Gracias a mi experiencia en el CRTO y de tontear mucho con windows y AD creo que me siento lo suficientemente capacitado como para explicarlo.

![](https://fallenangel666-htb.github.io/zzero.github.io//assets/images/patricio.jpeg)

Si eres nuevo, Kerberos es clave en Windows/AD – entiende esto y verás por qué es el eje de tantos pivots y escaladas.

![](https://fallenangel666-htb.github.io/zzero.github.io//assets/images/scooby.jpg)

## ¿Qué es Kerberos y por qué importa?

Kerberos es ese protocolo de autenticación basado en tickets que reemplazó a NTLM en Windows Server 2000. Se llama como el perro de hades, "guarda" accesos en redes distribuidas con SSO (Single Sign-On), sin mandar contraseñas por la red. Usa cripto simétrica para lidiar con redes inseguras – asume que paquetes se pueden sniffear o replay.

- **Ventajas**: SSO eficiente, no expone creds, resiste eavesdropping.
- **Asunciones**: Red hostil, así que todo gira en secretos compartidos (hashes).

En AD, el **Key Distribution Center (KDC)** (en DCs) es el que manda en el puticl#b: maneja users, hashes y tickets. Si own el KDC, own todo.

**Mención a ataques**: Aquí brillan **Golden Tickets** (forge TGTs con hash de krbtgt) o **Silver Tickets** (forge service tickets). Roba un secreto y impersonas a quien quieras – imagínate escalando un forest entero.

![](https://fallenangel666-htb.github.io/zzero.github.io//assets/images/goldentickets.png)

## Componentes Principales de Kerberos

- **KDC**: Incluye AS (Authentication Server) para TGTs iniciales, TGS (Ticket Granting Server) para service tickets, y la DB de hashes.
- **TGT (Ticket Granting Ticket)**: Boleto maestro post-login, para pedir más sin creds.
- **SPN (Service Principal Name)**: ID único de servicios, como `cifs/server.domain.com`.
- **Service Ticket (ST)**: Boleto para un servicio específico, cifrado con secreto del servicio.
- **PAC (Privileged Attribute Certificate)**: Info extra en tickets (RID, groups, UAC) – acelera checks sin query AD.

**Diagrama conceptual**:
```
[Cliente] <--> [KDC (AS/TGS en DC)] <--> [Servicio (e.g., CIFS en server)]
```

**Mención a ataques**: SPNs son oro en **Kerberoasting** (pide tickets y crackea hashes). PAC vulnerable si no validas – forge tickets y bypass.

![](https://fallenangel666-htb.github.io/zzero.github.io//assets/images/fry.jpg)
## Flujo de Autenticación: Paso a Paso

El core: AS, TGS, AP exchanges.

### 1. AS Exchange (Login Inicial)
- **AS-REQ**: Client manda user, domain, SPN (`krbtgt`), ciphers.
- Pre-auth (default): Timestamp cifrado con hash user.
- **AS-REP**: KDC verifica, emite TGT (cifrado con krbtgt) + session key.

Guarda TGT en LSASS.

### 2. TGS Exchange (Pedir Service Ticket)
- **TGS-REQ**: TGT + autenticador + SPN.
- **TGS-REP**: ST (cifrado con secreto servicio) + service session key.

KDC no chequea permisos – eso el servicio.

### 3. AP Exchange (Acceso al Servicio)
- **AP-REQ**: ST + autenticador.
- Servicio descifra, verifica. Opcional mutua auth con AP-REP.
- PAC validation: Servicio chequea firma con KDC.

**Diagrama full flow**:
```
AS: Login -> TGT
TGS: TGT -> ST
AP: ST -> Acceso
```

**Mención a ataques**: Sin pre-auth, **AS-REP Roasting**. O **Service Name Substitution**: Cambia SPN en ticket (e.g., TIME a CIFS) si misma cuenta – útil en delegation abuses.

![](https://fallenangel666-htb.github.io/zzero.github.io//assets/images/bob.jpg)

## Delegación: Acceso en Nombre de Otro

![](https://fallenangel666-htb.github.io/zzero.github.io//assets/images/del.png)

Para apps multi-tier (web -> DB), delegation deja al front-end actuar como user.

### Unconstrained Delegation
- Flag `TRUSTED_FOR_DELEGATION` en UAC.
- Client manda TGT en AP-REQ; front-end cachea y pide STs anywhere.

Peligroso: Compromete front-end, dump TGTs (e.g., Rubeus monitor).

**Mención a ataques**: Captura TGTs de admins para lateral – o fuerza auth con triggers como SpoolSample/PetitPotam, luego S4U2self para impersonar.

### Constrained Delegation (S4U)
- `msDS-AllowedToDelegateTo` lista SPNs permitidos.
- **S4U2self**: ST para sí mismo (impersona user).
- **S4U2proxy**: ST para back-end.
- Protocol Transition: Impersona sin Kerberos inicial (flag `TRUSTED_TO_AUTH_FOR_DELEGATION`).

**Mención a ataques**: Compromete máquina con constrained, impersona a SPNs (Rubeus s4u). O usa captured tickets para proxy.

### Resource-Based Constrained Delegation (RBCD)
- Desde 2012: Back-end controla via `msDS-AllowedToActOnBehalfOfOtherIdentity`.
- Solo write en atributo – no privs altos.

Ejemplo: Agrega front-end con PowerShell.
```
$front = Get-ADComputer -Identity 'lon-ws-1'
$back = Get-ADComputer -Identity 'lon-fs-1'
Set-ADComputer -Identity $back -PrincipalsAllowedToDelegateToAccount $front
```

**Mención a ataques**: Si write access + control de principal con SPN, agrega entries y abusa (e.g., S4U para access). Enumera con PowerView por WriteProperty en GUID específico.

## Trusts: Kerberos Cross-Domain y Forests

Kerberos no se queda en un domain porque para que facilitarnos la existencia – trusts habilitan cross-realm auth.

![](https://fallenangel666-htb.github.io/zzero.github.io//assets/images/wonka.jpg)

### Inter-Realm Tickets: Puente Cripto
Cross-domain: TGT normal no sirve – KDC foráneo no descifra. Usa **shared inter-realm keys**.

Flow:
1. TGS-REQ a tu KDC con SPN foráneo.
2. KDC emite inter-realm TGT (cifrado con shared key, SPN `krbtgt/foreign`).
3. TGS-REQ a foreign KDC con eso.
4. Foreign emite ST.

**Diagrama**:
```
[Tu Domain KDC] -> Inter-Realm TGT (shared key) -> [Foreign KDC] -> ST
```

Trust accounts: Cuenta como `PARTNER$` en trusted domain, pass = shared key.

**Mención a ataques**: Roba shared key (Mimikatz lsadump::trust), forge inter-realm TGTs para saltar.

### Tipos de Trusts
- **Parent/Child**: Auto, bidirectional transitive. Compromete child, escala a root con SID History en golden ticket (agrega SID Enterprise Admins).

  Ejemplo conceptual: Rubeus golden con /sids.

- **One-Way Inbound**: Acceso de trusted a trusting. Enumera foreign principals, forge inter-realm golden impersonando users/groups con acceso.

- **One-Way Outbound**: Stuck en trusting? Usa trust account + shared key para TGT como `PARTNER$`, enumera trusted.

- External/Forest: Non-transitive/transitive, con SID filtering (ignora foreign SIDs).

TDOs: `(objectClass=trustedDomain)` – chequea direction, attributes.

**Boundaries**: Forest-level – child no isolated.

**Mención a ataques**: SID History para escalar forests; forge trusts keys para flip directions.

## Conclusión

Considero que si sabes como funciona kerberos eres alguien que le gusta sufrir. el problema ? que a mi me gusta. kerberos es curioso pero necesario para un red team. auqnue azure esta cojiendo mucha fuerza y ni idea de que coño pasara con kerberos. Pero que vamos por ahora me voy a llorar por no interactuar con alguien de mi propia especie por etudiar kerberos :'3

Un saludo y que una ardilla no se os ponga a a bailar GANGNAM STYLE.

![](https://fallenangel666-htb.github.io/zzero.github.io//assets/images/simple.png)

*Refs: MS Docs, CRTO, homelab experiments. Vulnlab, HTB*

<iframe data-testid="embed-iframe" style="border-radius:12px" src="https://open.spotify.com/embed/track/61KYsWS25JXUO4fGb1138X?utm_source=generator&theme=0" width="100%" height="352" frameBorder="0" allowfullscreen="" allow="autoplay; clipboard-write; encrypted-media; fullscreen; picture-in-picture" loading="lazy"></iframe>
