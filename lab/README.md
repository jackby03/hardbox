# hardbox Testing Lab

Laboratorio local automatizado usando Vagrant + VirtualBox.
Una VM Ubuntu limpia, lista en 30 segundos, sin instalar nada manualmente.

## Instalacion (una sola vez)

1. Instalar [VirtualBox](https://www.virtualbox.org/) y [Vagrant](https://developer.hashicorp.com/vagrant/install)
2. Nada mas. No necesitas ISO, ni instalar Ubuntu manualmente.

## Uso

### Primer arranque

```powershell
# Descarga el box de Ubuntu (~500MB, solo la primera vez) y arranca la VM
vagrant up

# Corre las pruebas completas (compila + despliega + 8 tests)
.\lab\run-tests.ps1
```

### Comandos utiles

```powershell
.\lab\run-tests.ps1                  # Flujo completo: compilar y testear
.\lab\run-tests.ps1 -SkipBuild       # Solo testear (si ya compilaste)
.\lab\run-tests.ps1 -Clean           # Destruir VM despues del test
.\lab\run-tests.ps1 -Destroy         # Solo destruir la VM
```

### Dentro de la VM

```bash
vagrant ssh                           # Entrar a la VM
sudo hardbox audit --profile cis-level1 --format json
sudo hardbox apply --profile production --dry-run
exit
```

### Destruir y recrear (volver a estado limpio)

```powershell
vagrant destroy -f && vagrant up
.\lab\run-tests.ps1
```

## Pruebas incluidas

| # | Prueba | Que valida |
|---|---|---|
| 1 | `hardbox --version` | Binario funcional |
| 2 | `audit cis-level1 JSON` | Escaneo + reporte JSON valido |
| 3 | `audit production HTML` | Reporte HTML |
| 4 | `apply --dry-run` | Simulacion sin cambios |
| 5 | `extends: cis-level1` | Herencia de perfiles |
| 6 | `watch --max-runs 1` | Daemon de auditoria |
| 7 | `fleet --help` | Comando registrado |
| 8 | `serve` | Dashboard web responde 200 |

## Estructura

```
lab/
├── README.md          # Este archivo
├── Vagrantfile        # Definicion de la VM
├── run-tests.ps1      # Compilar -> desplegar -> testear
├── test-suite.sh      # Suite de pruebas (se ejecuta dentro de la VM)
├── last-results.txt   # Output de la ultima ejecucion
└── hardbox            # Binario compilado (gitignored)
```

## Troubleshooting

| Problema | Solucion |
|---|---|
| `vagrant up` falla | Verifica que VirtualBox este instalado y que VT-x este habilitado en BIOS |
| `hardbox binary not found` | Corre primero sin `-SkipBuild` |
| VM no responde en 192.168.56.50 | `vagrant ssh` y verifica `ip addr show` |
