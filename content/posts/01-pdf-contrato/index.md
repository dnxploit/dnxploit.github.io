---
title: "Un 'contrato en PDF' que era un troyano bancario"
date: 2026-07-16
draft: false
summary: "A mi madre le llegó un 'contrato'. Era un .apk. La frené a tiempo y lo desmonté: de un fichero falso hasta su servidor C2, atravesando tres capas de cifrado. Análisis estático."
tags: ["android", "malware-analysis", "reverse-engineering", "banking-trojan", "dropper"]
cover:
  alt: "Análisis de malware Android"
ShowToc: true
TocOpen: false
---

## TL;DR

A mi madre le llegó un fichero llamado `PDF_Contrato.apk` haciéndose pasar por un contrato en PDF. Le dije que ni se le ocurriera abrirlo, porque un contrato de verdad no termina en `.apk`.

Resulta que era un **dropper** de Android: una app cuya única gracia es llevar escondido, y cifrado, un segundo APK que es el malware de verdad. Lo analicé entero de forma **estática** y acabé sacando la dirección de su servidor de command & control (C2), pelando tres capas de cifrado por el camino.

El resumen de la Matrioshka:

```text
PDF_Contrato.apk (dropper)
    └─ assets/dbliqgnjl.dat  (payload cifrado con LCG+XOR)
         └─ APK real (troyano bancario)
              └─ strings ofuscados (repeating-key XOR)
                   └─ config cifrada (AES/CBC + PBKDF2)
                        └─ C2: 190.102.43.149
```

---

## 1. Primer vistazo: huele a chamusquina

Antes de descompilar nada, ya había suficientes banderas rojas para montar un desfile:

- **Se disfraza de PDF.** Un contrato legítimo es un `.pdf`. Este era un `.apk`, o sea, una aplicación de Android. Es como recibir un "documento Word" que pesa 12 MB y pide permiso para encender tu cámara.
- **Package que imita al sistema.** `com.android.system.qspaas` — elige ese nombre a propósito para camuflarse entre los componentes reales de Android y que no te llame la atención en la lista de apps.
- **Un asset gigante con entropía máxima.** Dentro había un `assets/dbliqgnjl.dat` de ~12 MB con **entropía 8.0/8.0**. Traducido: los datos son puro ruido aleatorio, y eso solo pasa cuando algo está cifrado o comprimido. Un fichero honesto tiene patrones.
- **El código visible era ridículamente pequeño.** El `classes.dex` a la vista pesaba 72 KB frente a los 12 MB del `.dat`.

Los permisos del dropper eran cinco y de lo más inocentes. El malware de verdad estaba durmiendo dentro del `.dat`.

---

## 2. Primera capa: descifrar el payload (LCG + XOR)

El cargador (`MainActivity.L()`) hacía tres cosas: abrir el `.dat`, tirar los primeros 16 bytes de cabecera, y descifrar el resto con un **generador congruencial lineal (LCG) + XOR**.

Un LCG es básicamente una máquina de generar números "aleatorios" a partir de una semilla: le das un número, lo mete en una fórmula fija y escupe el siguiente, una y otra vez. Como no es aleatorio de verdad (si sabes la semilla y la fórmula, reproduces la secuencia entera), sirve de perlas para cifrar... y también para descifrar, que es justo lo que nos interesa.

```python
def decrypt_stage1(data):
    payload = data[16:]           # tira los 16 bytes de cabecera
    out = bytearray(payload)
    j = 276813                    # la semilla
    for i in range(len(out)):
        j = (j * 1664525 + 1013904223) & 0xFFFFFFFF   # LCG clásico (Numerical Recipes)
        out[i] ^= (j >> 24) & 0xFF                     # XOR con el byte alto
    return out
```

Las constantes `1664525` y `1013904223` son las de toda la vida del LCG de *Numerical Recipes*, el desarrollador del malware ni se molestó en inventarse unas propias.

**Resultado:** los primeros bytes del output eran `50 4B 03 04`, que en el mundo de los ficheros es la firma de un ZIP. Y un APK no es más que un ZIP con ínfulas. Bingo: el `.dat` era **un segundo APK completo**.

---

## 3. El payload real: aquí empieza lo feo

El APK descifrado (`ntqe.zyeyou.rgmbjcs`) sigue llamandose "PDF Contrato" de cara a la galería, pero ahora pide **24 permisos**:

| Permiso | Para qué lo quiere |
|---|---|
| `READ_SMS` / `SEND_SMS` | Leer los SMS del banco (los códigos OTP) y propagarse |
| `FOREGROUND_SERVICE_MEDIA_PROJECTION` | Grabar la pantalla en directo |
| `READ_CONTACTS` / `WRITE_CONTACTS` | Robar la agenda y seguir esparciéndose |
| `CAMERA` / `RECORD_AUDIO` | Cámara y micro, por si acaso |
| `MANAGE_EXTERNAL_STORAGE` | Acceso total a tus ficheros |
| `ACCESS_FINE_LOCATION` | Saber dónde estás |
| `RECEIVE_BOOT_COMPLETED` | Volver a arrancar cada vez que enciendes el móvil |

En el código hay una clase que implementa `AccessibilityService.TakeScreenshotCallback`: captura la pantalla, la reescala, la comprime en WEBP, la codifica en Base64 y la manda en un JSON al C2, es decir, le hace fotos a todo lo que ves, incluida la app del banco, y se las envía a alguien. La comunicación va por `HttpURLConnection` y WebSocket sobre TLS (`wss://`), o sea, cifrada para que no cante en la red.

---

## 4. Segunda capa: strings ofuscados (repeating-key XOR)

Los textos importantes no están a la vista. Se descifran en tiempo de ejecución con una función `mb0.a(byte[] datos, byte[] clave)` que resultó ser un **XOR de clave repetida**: coge la clave y la va repitiendo en bucle sobre los datos.

```python
def mb0_a(data, key):
    out = bytearray(len(data))
    i2 = 0
    for i in range(len(data)):
        if i2 >= len(key):
            i2 = 0            # se acabó la clave, vuelve al principio
        out[i] = data[i] ^ key[i2]
        i2 += 1
    return out.decode('utf-8')
```

Aplicándolo, salieron a la luz cosas muy interesantes:

- `"Servicio de accesibilidad"` y `"Esta aplicación requiere permiso de acceso para funcionar..."` → el guion del **engaño** para que la víctima le active la Accesibilidad "porque si no, la app no va". Spoiler: la app va perfectamente; lo que quiere es el control.
- `"AES/CBC/PKCS5Padding"` y `"PBKDF2WithHmacSHA1"` → el esquema de cifrado de su configuración.
- `"/yaarsa/private/"` y `"log_error.php"` → la ruta del servidor.

---

## 5. Tercera capa: la config cifrada (AES + PBKDF2)

La lista de servidores C2 estaba cifrada con **AES/CBC/PKCS5Padding**, y la clave no venía puesta directamente: se derivaba con **PBKDF2WithHmacSHA1** dándole 65.536 vueltas.

PBKDF2 es, en esencia, coger una contraseña y pasarla por la batidora 65.536 veces para convertirla en una clave. La idea es que reventarla a fuerza bruta salga carísimo. El detalle simpático es que el malware llevaba la contraseña, la sal y el IV **también escondidos** con el XOR de antes. Vamos, que escondió la llave debajo del felpudo... y luego escondió el felpudo.

| Ingrediente | Valor |
|---|---|
| Password | `4814780584699673` |
| Salt | `2894356330652558` |
| IV | `2230209522049090` |
| Blob cifrado | `dDn4Q/Qt5iSze/PL+8nLvQ==` |

```python
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1
import base64

key = PBKDF2("4814780584699673", "2894356330652558".encode(),
             dkLen=16, count=65536, hmac_hash_module=SHA1)
raw = base64.b64decode("dDn4Q/Qt5iSze/PL+8nLvQ==")
pt  = AES.new(key, AES.MODE_CBC, "2230209522049090".encode()).decrypt(raw)
print(pt)   # -> b'190.102.43.149<'
```

Y ahí apareció, por fin, la cara del malo: **`190.102.43.149`**. La URL completa a la que manda lo robado:

```text
http://190.102.43.149/yaarsa/private/log_error.php
```

---

## 6. IOCs

**Dropper**
- Package: `com.android.system.qspaas`
- SHA-256: `a3242742c9028388ecf7beecf81a749b772f83b83ab9a809d2229284642be229`

**Payload**
- Package: `ntqe.zyeyou.rgmbjcs`
- SHA-256: `57e5ba7bd48dc9786fc1c2beb14162046dd9c7788b34b495a13119606982ec74`

**Red**
- C2: `190.102.43.149`
- URL: `http://190.102.43.149/yaarsa/private/log_error.php`

---

## 7. Alcance y ética

Todo esto se hizo con **análisis estático**. La muestra **no se ejecutó** en ningún momento, y el servidor C2 **no lo toqué**: ni me conecté, ni lo escaneé, ni le mandé un triste ping. Su dirección la dejo aquí solo como indicador para que se pueda bloquear.

---

## 8. Consejos para quien no se dedica a esto

- Un contrato de verdad es un **PDF**. Si te llega un **`.apk`, es una aplicación** — y en este contexto, un virus con lazo de regalo. Un documento nunca acaba en `.apk`.
- Si una app te pide activar el **"Servicio de accesibilidad"** para "poder funcionar", desconfía. Es la puerta grande por la que estos troyanos se cuelan para verlo y controlarlo todo.
- No instales APKs de fuera de Google Play, sobre todo los que llegan por WhatsApp o email con prisas y urgencias. La urgencia es parte del truco.

---

*Herramientas: jadx · androguard · apktool · Python (pycryptodome) · mucho clic derecho → "Find usage" en el bytecode.*