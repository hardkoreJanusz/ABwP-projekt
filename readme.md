##**Dokumentacja Aplikacji**

1. Opis aplikacji

Aplikacja demonstracyjna ma na celu pokazanie działania szyfrowania AES (Advanced Encryption Standard) oraz ataku brute force w celu odszyfrowania danych. Składa się z dwóch głównych funkcji:

  a. Szyfrowanie wiadomości: Wiadomość tekstowa jest szyfrowana za pomocą algorytmu AES w trybie CBC (Cipher Block Chaining), z użyciem klucza wyprowadzonego z hasła użytkownika.

  b. Atak brute force: Próba odgadnięcia hasła poprzez iteracyjne sprawdzanie możliwych kombinacji haseł (od 0 do 999). Jeśli hasło zostanie odgadnięte, aplikacja wyświetla odszyfrowaną wiadomość.

Aplikacja prezentuje zarówno zastosowanie kryptografii, jak i jej potencjalne słabości, jeśli hasło jest zbyt krótkie lub proste.


2. Opis użytych algorytmów

AES (Advanced Encryption Standard)

- Zastosowanie: AES w trybie CBC został użyty do szyfrowania wiadomości tekstowej. Algorytm ten wykorzystuje klucz o długości 256 bitów oraz wektor inicjalizujący (IV) do zapewnienia losowości każdego procesu szyfrowania.

- Działanie: Wiadomość jest dzielona na bloki o stałej długości (128 bitów). Każdy blok jest szyfrowany z uwzględnieniem poprzedniego, co zwiększa bezpieczeństwo.

- Bezpieczeństwo: AES w trybie CBC jest bezpieczny, jeśli:

    a. Klucz jest trudny do odgadnięcia.

    b. IV jest generowany losowo i unikalnie dla każdej operacji szyfrowania.


PBKDF2 (Password-Based Key Derivation Function 2)

- Zastosowanie: PBKDF2 jest używany do wyprowadzania klucza kryptograficznego z hasła użytkownika i losowej soli.

- Działanie: Proces polega na wielokrotnym stosowaniu funkcji skrótu (SHA-256) na haśle i soli, co utrudnia ataki brute force oraz ataki słownikowe.

- Bezpieczeństwo: Iteracje i sól zwiększają czas potrzebny na odgadnięcie klucza, czyniąc takie ataki bardziej kosztownymi.


SHA-256 (Secure Hash Algorithm 256-bit)

- Zastosowanie: SHA-256 jest wykorzystywany w PBKDF2 do generowania klucza kryptograficznego.

- Bezpieczeństwo: Jest odporny na kolizje i trudny do odwrócenia, co czyni go bezpiecznym do zastosowań kryptograficznych.

Padding PKCS7

- Zastosowanie: Wiadomość, która nie jest wielokrotnością rozmiaru bloku AES (128 bitów), jest uzupełniana zgodnie z PKCS7, aby umożliwić poprawne szyfrowanie.


3. Opis zastosowanego ataku (brute force)

Atak brute force

- Opis: Atak brute force polega na przeszukiwaniu wszystkich możliwych kombinacji haseł, aż do znalezienia poprawnego. W aplikacji jest to realizowane przez iteracyjne testowanie haseł z zakresu od 0 do 999. Jeśli hasło jest poprawne, wiadomość zostaje odszyfrowana i wyświetlona.

- Etapy ataku:

    a. Odczytanie szyfrogramu, soli i wektora inicjalizującego (IV).

    b. Wyprowadzanie klucza z każdego hasła za pomocą PBKDF2.

    c. Próba odszyfrowania wiadomości za pomocą AES.

    d. Weryfikacja, czy odszyfrowana wiadomość jest poprawna.

Ograniczenia: Atak brute force działa tylko wtedy, gdy:

  a. Przestrzeń kluczy (liczba możliwych haseł) jest niewielka.

  b. Hasło jest krótkie lub proste.
    

4. Opis przeciwdziałania takim atakom

Aby zabezpieczyć aplikację przed atakami brute force, należy wprowadzić następujące środki:

a. Zasady tworzenia silnych haseł:

 - Minimalna długość: Hasło powinno mieć co najmniej 12 znaków.

 - Zróżnicowanie znaków: Hasło powinno zawierać litery (duże i małe), cyfry oraz znaki specjalne.

 - Brak wzorców: Unikać oczywistych wzorców, takich jak "12345" lub "password".

 b. Użycie mechanizmów ochronnych:

   - PBKDF2 z dużą liczbą iteracji: Większa liczba iteracji (np. 500 000) znacząco zwiększa czas potrzebny na odgadnięcie hasła.

  - Losowa sól: Sól powinna być unikalna dla każdej operacji szyfrowania, aby zapobiec atakom słownikowym.

 c. Ograniczenie liczby prób logowania:

   - Blokowanie konta po określonej liczbie nieudanych prób.

   - Wprowadzenie opóźnień między kolejnymi próbami logowania.

  d. Monitorowanie i audyt:

   - Analiza logów pod kątem podejrzanych aktywności (np. wiele nieudanych prób logowania).

   - Stosowanie systemów wykrywania ataków (IDS/IPS).

   e. Edukacja użytkowników:

   - Informowanie użytkowników o ryzykach związanych z używaniem prostych haseł.

   - Wdrażanie zasad zmiany hasła co określony czas.
