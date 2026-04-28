FROM ocaml/opam:latest

COPY --chown=opam:opam . .

RUN opam install dune -y
RUN opam exec -- dune pkg lock
RUN sudo apt-get update && sudo apt-get install -y $(opam exec -- dune show depexts)
RUN opam exec -- dune build ./server.exe

EXPOSE 8080

CMD ["./_build/default/server.exe"]
