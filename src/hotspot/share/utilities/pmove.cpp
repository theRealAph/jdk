enum class Status { ToMove, BeingMoved, Moved };

template <typename Reg, typename TempFn, typename MoveFn>
class ParallelMover {
  GrowableArray<Reg> *src;
  GrowableArray<Reg> *dst;
  const TempFn tmp;
  const MoveFn move;

  ParallelMover(GrowableArray<Reg> *_src,
                GrowableArray<Reg> *_dst,
                const TempFn _tmp,
                const MoveFn _move)
    : _src(src), _dst(dst), _tmp(tmp), _move(move), {
    assert(_src->length() == _dst->length(), "mismatch");
  }

  const std::size_t n = src.size();
  GrowableArray<Status> status(n, Status::ToMove);

  // Recursive, like the original: emitting `dst->at(i) = src->at(i)`
  // first requires clearing every j that still needs to read the
  // register dst->at(i) is about to clobber.
  void move_one(size_t i) {
    if (src->at(i) == dst->at(i)) {
      return;
    }
    status->at(i) = Status::BeingMoved;
    for (size_t j = 0; j < n; ++j) {
      if (src->at(j) != dst->at(i)) {
        continue;
      }
      switch (status->at(j)) {
        case Status::ToMove:
          move_one(j);
          break;
        case Status::BeingMoved: {
          // j is an ancestor in the recursion, so we have closed a
          // cycle. Spill its source to scratch and read from there.
          const Reg scratch = tmp(src->at(j));
          _move(scratch, src->at(j));
          src->at(j) = scratch;
          break;
        }
        case Status::Moved:
          break;
      }
    }
    _move(dst->at(i), src->at(i));
    status->at(i) = Status::Moved;
  }

  void doIt() {
    for (std::size_t i = 0; i < n; ++i) {
      if (status->at(i) == Status::ToMove) {
        move_one(i);
      }
    }
  }
}

