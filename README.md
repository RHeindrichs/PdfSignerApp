# PdfSignerApp

PdfSignerApp ist eine Java-Anwendung zum Signieren von PDFs.

## Voraussetzungen

- Java 17+ (oder kompatibles JDK)
- Gradle (oder das mitgelieferte Gradle Wrapper-Script `./gradlew`)

## Build

### JAR erstellen

```bash
./gradlew clean jar
```

Die Datei `app.jar` befindet sich anschließend unter `build/libs/app.jar`.

### ZIP-Distribution mit `app.jar`

Um eine ZIP-Distribution zu erzeugen, die die `app.jar` sowie alle Runtime-Abhängigkeiten enthält, nutze folgenden Parameter:

```bash
./gradlew clean jar distZip
```

Das ZIP findest du danach unter:

```
build/distributions/pdfsigner.zip
```

## Starten

```bash
java -jar build/libs/app.jar
```
